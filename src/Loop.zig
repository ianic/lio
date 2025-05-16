const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;
const testing = std.testing;

const SyscallError = @import("errno.zig").Error;

fn success(cqe: linux.io_uring_cqe) SyscallError!void {
    switch (cqe.err()) {
        .SUCCESS => return,
        else => |errno| return @import("errno.zig").toError(errno),
    }
}

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_SQPOLL,
    /// Number of kernel registered file descriptors
    fd_nr: u16,
};

pub const Op = struct {
    ptr: ?*anyopaque = null,
    callback: *const fn (Op, linux.io_uring_cqe) void = noopCallback,

    const noopCallback = struct {
        fn noop(_: Op, _: linux.io_uring_cqe) void {}
    }.noop;

    /// Replace callback with noop callback. Enables ptr to be destroyed.
    fn detach(self: *Op, context: *anyopaque) void {
        assert(self.ptr == context);
        self.callback = noopCallback;
    }
};

const Loop = @This();
const yes_value: u32 = 1;
const yes_socket_option = std.mem.asBytes(&yes_value);
const no_user_data: u64 = std.math.maxInt(u64);
const timer_user_data: u64 = no_user_data - 1;

allocator: mem.Allocator,
ring: linux.IoUring,
op_list: std.ArrayList(Op),
next_op_idx: usize = 0,
metric: struct {
    /// Current number of in kernel operations
    active_op: usize = 0,
    /// Total number of processed operations
    processed_op: usize = 0,
} = .{},
tick_timer_ts: ?linux.kernel_timespec = null,
next_buffer_group_id: u16 = 0,

pub fn init(allocator: mem.Allocator, opt: Options) !Loop {
    var ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer ring.deinit();
    try ring.register_files_sparse(opt.fd_nr);
    return .{
        .allocator = allocator,
        .ring = ring,
        .op_list = try .initCapacity(allocator, @min(16, opt.fd_nr)),
    };
}

pub fn deinit(self: *Loop) void {
    self.op_list.deinit();
    self.ring.deinit();
}

pub fn tickNr(self: *Loop, wait_nr: u32) !void {
    _ = try self.ring.submit_and_wait(wait_nr);
    self.processCompletions();
}

/// Get completions and call operation callback for each completion.
fn processCompletions(self: *Loop) void {
    var ring = &self.ring;
    // Repeat in the case of overlapping ring
    while (true) {
        const ready = ring.cq_ready();
        if (ready == 0) break;
        // Peek list of ready cqes
        const head = ring.cq.head.* & ring.cq.mask;
        const tail = @min(ring.cq.cqes.len - head, ready);
        const cqes = ring.cq.cqes[head..][0..tail];
        // Call callback of each completion
        for (cqes) |cqe| {
            if (cqe.user_data == no_user_data) {
                // cqe without Op in userdata
                continue;
            }
            if (cqe.user_data == timer_user_data) {
                self.tick_timer_ts = null;
                continue;
            }
            const op: Op = self.op_list.items[cqe.user_data];
            if (!flagMore(cqe)) {
                // Done with operation mark it as unused.
                self.op_list.items[cqe.user_data] = .{};
                self.metric.active_op -= 1;
            }
            //std.debug.print("op: {} cqe: {}\n", .{ op, cqe });
            op.callback(op, cqe);
            self.metric.processed_op +%= 1;
        }
        ring.cq_advance(@intCast(cqes.len));
        if (cqes.len == ready) break;
    }
}

pub fn tick(self: *Loop) !void {
    return self.tickNr(1);
}

pub fn runFor(self: *Loop, ms: u64) !void {
    if (self.tick_timer_ts == null) {
        const sec = ms / std.time.ms_per_s;
        const nsec = (ms - sec * std.time.ms_per_s) * std.time.ns_per_ms;
        self.tick_timer_ts = .{ .sec = @intCast(sec), .nsec = @intCast(nsec) };
        try self.tickTimer(&self.tick_timer_ts.?);
    }
    while (self.tick_timer_ts != null) {
        _ = try self.ring.submit_and_wait(1);
        self.processCompletions();
    }
}

/// Tick loop while there is active operations
pub fn drain(self: *Loop) !void {
    while (self.metric.active_op > 0)
        try self.tick();
}

fn flagMore(cqe: linux.io_uring_cqe) bool {
    return cqe.flags & linux.IORING_CQE_F_MORE > 0;
}

/// Number of unused submission queue entries
/// Matched liburing io_uring_sq_space_left
pub fn submissionQueueSpaceLeft(self: *Loop) u32 {
    return @as(u32, @intCast(self.ring.sq.sqes.len)) - self.ring.sq_ready();
}

pub const SubmitError = error{
    SystemResources,
    FileDescriptorInvalid,
    FileDescriptorInBadState,
    CompletionQueueOvercommitted,
    SubmissionQueueEntryInvalid,
    BufferInvalid,
    RingShuttingDown,
    OpcodeNotSupported,
    Unexpected,
};

pub const PrepareError = SubmitError || error{OutOfMemory};

fn ensureSubmissionQueueCapacity(self: *Loop, count: u32) SubmitError!void {
    assert(count <= self.ring.sq.sqes.len);
    while (self.submissionQueueSpaceLeft() < count) {
        _ = self.ring.submit() catch |err| switch (err) {
            error.SignalInterrupt => continue,

            error.SystemResources => return error.SystemResources,
            error.FileDescriptorInvalid => return error.FileDescriptorInvalid,
            error.FileDescriptorInBadState => return error.FileDescriptorInBadState,
            error.CompletionQueueOvercommitted => return error.CompletionQueueOvercommitted,
            error.SubmissionQueueEntryInvalid => return error.SubmissionQueueEntryInvalid,
            error.BufferInvalid => return error.BufferInvalid,
            error.RingShuttingDown => return error.RingShuttingDown,
            error.OpcodeNotSupported => return error.OpcodeNotSupported,
            error.Unexpected => return error.Unexpected,
        };
    }
}

/// Returns Op and index to that Op in op_list
fn getOp(self: *Loop) error{OutOfMemory}!struct { *Op, usize } {
    // Find existing free operation
    {
        const ops = self.op_list.items;
        // find unused op with higher index than the last one
        for (self.next_op_idx..ops.len) |idx| {
            const op = &ops[idx];
            if (op.ptr == null) return .{ op, idx };
        }
        // find unused from start of the list
        for (0..@min(self.next_op_idx, ops.len)) |idx| {
            const op = &ops[idx];
            if (op.ptr == null) return .{ op, idx };
        }
    }
    // Increase operations list
    try self.op_list.append(.{});
    const idx = self.op_list.items.len - 1;
    return .{ &self.op_list.items[idx], idx };
}

fn prepareOp(
    self: *Loop,
    ptr: *anyopaque,
    callback: *const fn (Op, linux.io_uring_cqe) void,
) error{OutOfMemory}!usize {
    const op, const idx = try self.getOp();
    self.metric.active_op += 1;
    self.next_op_idx = idx + 1;
    op.* = .{
        .ptr = ptr,
        .callback = callback,
    };
    return idx;
}

/// Get io_uring direct socket. If there are no free socket we will get:
/// error.FileTableOverflow.
pub fn socket(
    self: *Loop,
    domain: u32,
    socket_type: u32,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), SyscallError!linux.fd_t) void,
) PrepareError!usize {
    const wrap = struct {
        fn callback(op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@ptrCast(op.ptr orelse return)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    };
    const op_idx = try self.prepareOp(context, wrap.callback);

    try self.ensureSubmissionQueueCapacity(1);
    _ = self.ring.socket_direct_alloc(op_idx, domain, socket_type, 0, 0) catch |err| switch (err) {
        error.SubmissionQueueFull => unreachable,
    };

    return op_idx;
}

/// error.AddressAlreadyInUse
pub fn listen(
    self: *Loop,
    fd: linux.fd_t,
    /// Lifetime has to be until completion is received
    addr: *std.net.Address,
    opt: std.net.Address.ListenOptions,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), SyscallError!void) void,
) PrepareError!usize {
    const wrap = struct {
        fn callback(op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@ptrCast(op.ptr orelse return)),
                if (success(cqe)) {} else |err| err,
            );
        }
    };
    const op_idx = try self.prepareOp(context, wrap.callback);

    try self.ensureSubmissionQueueCapacity(if (opt.reuse_address) 4 else 2);
    var sqe: *linux.io_uring_sqe = undefined;
    // Hardlink ensures that the last operation will get meaningful error. With
    // (soft)link in the case of error in bind onComplete will always get
    // error.OperationCanceled.
    if (opt.reuse_address) {
        sqe = self.ring.setsockopt(no_user_data, fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option) catch unreachable;
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = self.ring.setsockopt(no_user_data, fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option) catch unreachable;
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = self.ring.bind(no_user_data, fd, &addr.any, addr.getOsSockLen(), 0) catch unreachable;
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = self.ring.listen(op_idx, fd, opt.kernel_backlog, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    return op_idx;
}

/// General syscall errors:
///   error.OperationCanceled
///   error.InterruptedSystemCall
/// Connect specific syscall errors to handle:
/// ref: https://man7.org/linux/man-pages/man2/connect.2.html
/// Network errors
///   error.ConnectionRefused, // ECONNREFUSED
///   error.NetworkIsUnreachable, // ENETUNREACH
///   error.NoRouteToHost, // EHOSTUNREACH
///   error.ConnectionTimedOut, // ETIMEDOUT
///   error.ConnectionResetByPeer, // ECONNRESET
/// Other documented to consider
///   error.AddressAlreadyInUse, // EADDRINUSE
///   error.OperationAlreadyInProgress, // EALREADY
///   error.OperationNowInProgress, // EINPROGRESS
///   error.TryAgain, // EAGAIN
///   error.TransportEndpointIsAlreadyConnected, //  EISCONN
pub fn connect(
    self: *Loop,
    fd: linux.fd_t,
    addr: *std.net.Address,
    timeout: ?*linux.kernel_timespec,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), SyscallError!void) void,
) PrepareError!usize {
    const wrap = struct {
        fn callback(op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@ptrCast(op.ptr orelse return)),
                if (success(cqe)) {} else |err| err,
            );
        }
    };
    const op_idx = try self.prepareOp(context, wrap.callback);

    try self.ensureSubmissionQueueCapacity(2);
    var sqe = self.ring.connect(op_idx, fd, &addr.any, addr.getOsSockLen()) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (timeout) |t| {
        sqe.flags |= linux.IOSQE_IO_LINK;
        sqe = self.ring.link_timeout(no_user_data, t, 0) catch unreachable;
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }

    return op_idx;
}

pub fn accept(
    self: *Loop,
    fd: linux.fd_t,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), SyscallError!linux.fd_t) void,
) PrepareError!usize {
    const wrap = struct {
        fn callback(op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@ptrCast(op.ptr orelse return)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    };
    const op_idx = try self.prepareOp(context, wrap.callback);

    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.accept_direct(op_idx, fd, null, null, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    return op_idx;
}

/// Returns 0 on graceful shutdown.
///   error.ConnectionResetByPeer when remote host sends RST packet
/// Common syscall errors to handle:
///   error.OperationCanceled
///   error.InterruptedSystemCall
pub fn recv(
    self: *Loop,
    fd: linux.fd_t,
    buffer: []u8,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), SyscallError!u32) void,
) PrepareError!usize {
    const wrap = struct {
        fn callback(op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@ptrCast(op.ptr orelse return)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    };
    const op_idx = try self.prepareOp(context, wrap.callback);

    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.recv(op_idx, fd, .{ .buffer = buffer }, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    return op_idx;
}

/// Send on closed socket will return:
///   error.BrokenPipe - send on closed socket
///   error.ConnectionResetByPeer - send on forcefully closed socket (RST)
/// Common syscall errors to handle:
///   error.OperationCanceled
///   error.InterruptedSystemCall
pub fn send(
    self: *Loop,
    fd: linux.fd_t,
    buffer: []const u8,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), SyscallError!u32) void,
) PrepareError!usize {
    const wrap = struct {
        fn callback(op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@ptrCast(op.ptr orelse return)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    };
    const op_idx = try self.prepareOp(context, wrap.callback);

    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.send(op_idx, fd, buffer, linux.MSG.WAITALL | linux.MSG.NOSIGNAL) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    return op_idx;
}

/// Close file descriptor and cancel any pending operations on that fd.
pub fn close(self: *Loop, fd: linux.fd_t) SubmitError!void {
    if (fd < 0) return;
    try self.ensureSubmissionQueueCapacity(2);

    // close socket
    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.close_direct(no_user_data, @intCast(fd)) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    // cancel any fd operations
    sqe = self.ring.get_sqe() catch unreachable;
    sqe.prep_cancel_fd(fd, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe.user_data = no_user_data;
}

/// Cancel single operation by index.
pub fn cancel(self: *Loop, idx: usize) SubmitError!void {
    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.cancel(no_user_data, idx, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Detach (don't call callback when completed) single operation by index and
/// cancel that operation if still active.
pub fn detach(self: *Loop, idx: usize, ctx: *anyopaque) !void {
    if (idx >= self.op_list.items.len) return;
    const op = &self.op_list.items[idx];
    if (op.ptr) |op_ptr| if (op_ptr == ctx) {
        op.detach(ctx);
        try self.cancel(idx);
    };
}

/// Detach all operations for some context and cancel active operations.
pub fn detachAll(self: *Loop, ctx: *anyopaque) SubmitError!void {
    for (self.op_list.items, 0..) |*op, idx| if (op.ptr) |op_ptr| if (op_ptr == ctx) {
        op.detach(ctx);
        try self.cancel(idx);
    };
}

fn tickTimer(self: *Loop, ts: *linux.kernel_timespec) SubmitError!void {
    try self.ensureSubmissionQueueCapacity(1);
    _ = self.ring.timeout(timer_user_data, ts, 0, 0) catch unreachable;
}

pub fn initBufferGroup(
    self: *Loop,
    buffer_size: u32,
    buffers_count: u16,
) !linux.IoUring.BufferGroup {
    const bg = try linux.IoUring.BufferGroup.init(
        &self.ring,
        self.allocator,
        self.next_buffer_group_id,
        buffer_size,
        buffers_count,
    );
    self.next_buffer_group_id += 1;
    return bg;
}

test "socket" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 1,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            self.call_count += 1;
            self.err = null;
            self.fd = err_fd catch |err| brk: {
                self.err = err;
                break :brk null;
            };
        }
    };
    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    { // success
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.tickNr(1);
        try testing.expectEqual(1, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    { // success
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.tickNr(1);
        try testing.expectEqual(2, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    const used_fd = ctx.fd.?;
    { // fail no more fds
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.tickNr(1);
        try testing.expectEqual(3, ctx.call_count);
        try testing.expect(ctx.err != null);
        try testing.expect(ctx.fd == null);
        try testing.expectEqual(ctx.err.?, error.FileTableOverflow);
    }
    { // return one used fd to the kernel
        _ = try loop.ring.close_direct(no_user_data, @intCast(used_fd));
        try loop.tickNr(1);
    }
    { // success
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.tickNr(1);
        try testing.expectEqual(4, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
}

test "ensure unused sqes pushes sqes to the kernel" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 2,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            _ = self;
            _ = err_fd catch unreachable;
        }
    };
    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    // 2 entries but 3 prepared sqe
    // there was submit in ensureUnusedSqes
    _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
    _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
    _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
}

test "OutOfMemory on operations list unable to grow" {
    const ops_count = 8;
    var buf: [ops_count * @sizeOf(Op)]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var loop = try Loop.init(fba.allocator(), .{
        .entries = 2,
        .fd_nr = ops_count,
    });
    defer loop.deinit();
    // fixed buffer allocator is full
    try testing.expectEqual(buf.len, fba.end_index);

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            _ = self;
            _ = err_fd catch unreachable;
        }
    };

    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    try testing.expectEqual(ops_count, loop.op_list.capacity);
    for (0..ops_count) |_| {
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
    }
    try testing.expectEqual(ops_count, loop.op_list.items.len);
    _ = loop.socket(domain, socket_type, &ctx, Ctx.onSocket) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => unreachable,
    };
    unreachable;
}

test "listen (linked request) should return meaningful error" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 4,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        err: ?anyerror = null,

        fn onListen(self: *Self, _err: anyerror!void) void {
            _ = _err catch |e| {
                self.err = e;
            };
        }
    };

    var ctx: Ctx = .{};
    var addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 0);

    _ = try loop.listen(0xffff, &addr, .{ .reuse_address = true }, &ctx, Ctx.onListen);
    try loop.tickNr(4);
    try testing.expectEqual(error.BadFileNumber, ctx.err.?);
}

test "tcp server" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 16,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Server = struct {
        const Self = @This();
        addr: std.net.Address,
        loop: *Loop,
        buffer: [128]u8 = undefined,
        buffer_pos: usize = 0,
        listen_fd: ?linux.fd_t = null,
        conn_fd: ?linux.fd_t = null,
        conn_count: usize = 0,

        fn start(self: *Self) !void {
            _ = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, onSocket);
        }

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            const fd = err_fd catch unreachable;
            self.listen_fd = fd;
            _ = self.loop.listen(
                fd,
                &self.addr,
                .{ .reuse_address = true },
                self,
                onListen,
            ) catch unreachable;
        }

        fn onListen(self: *Self, maybe_err: anyerror!void) void {
            _ = maybe_err catch unreachable;
            _ = self.loop.accept(self.listen_fd.?, self, onAccept) catch unreachable;
        }

        fn onAccept(self: *Self, err_fd: anyerror!linux.fd_t) void {
            const fd = err_fd catch unreachable;
            self.conn_fd = fd;
            _ = self.loop.recv(fd, self.buffer[self.buffer_pos..], self, onRecv) catch unreachable;
        }

        fn onRecv(self: *Self, err_n: anyerror!u32) void {
            const n = err_n catch unreachable;
            self.conn_count += 1;
            self.buffer_pos += n;
            self.loop.close(self.conn_fd.?) catch unreachable;
            self.conn_fd = null;
            _ = self.loop.accept(self.listen_fd.?, self, onAccept) catch unreachable;
        }
    };

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9990);
    var server: Server = .{
        .loop = &loop,
        .addr = addr,
    };

    try server.start();
    var thr = try std.Thread.spawn(.{}, testSend, .{addr});
    while (server.conn_count < 4) {
        try loop.tickNr(1);
    }
    thr.join();

    try testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3 }, server.buffer[0..server.buffer_pos]);
}

fn testSend(addr: std.net.Address) void {
    var n: usize = 0;
    while (n < 4) {
        var stream = std.net.tcpConnectToAddress(addr) catch |err| switch (err) {
            error.ConnectionRefused => continue,
            else => unreachable,
        };
        stream.writeAll(&[_]u8{@intCast(n)}) catch unreachable;
        stream.close();
        n += 1;
    }
}

test "size" {
    try testing.expectEqual(16, @sizeOf(Op));
}
