const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;
const testing = std.testing;
const log = std.log.scoped(.loop);

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
    const Callback = *const fn (*Loop, Op, linux.io_uring_cqe) void;

    ref: ?*?u32 = null,
    callback: ?Callback = null,
    args: union(enum) {
        recv: struct { buffer_group_id: u16 },
        // recv: union(enum) {
        //     buffer_group_id: u16,
        //     buffer: []u8,
        // },
        // send: []const u8,
    } = undefined,

    /// Break connection with parent, replace callback with noop callback.
    fn detach(self: *Op) void {
        // Clear parent reference to the operation
        if (self.ref) |ref| ref.* = null;
        self.callback = null;
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
next_free_op: usize = 0,
metric: struct {
    /// Current number of in kernel operations
    active_op: usize = 0,
    /// Total number of processed operations
    processed_op: usize = 0,
    /// Total number of successful receives into provieded buffers
    recv: usize = 0,
    /// Total number of receive operations failed with no buffer available
    recv_no_buffer: usize = 0,
} = .{},
tick_timer_ts: ?linux.kernel_timespec = null,
buffer_groups: std.ArrayListUnmanaged(linux.IoUring.BufferGroup) = .empty,

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
    for (self.buffer_groups.items) |*bg| bg.deinit(self.allocator);
    self.buffer_groups.deinit(self.allocator);
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
            const idx = cqe.user_data;
            const op: Op = self.op_list.items[idx];
            if (!flagMore(cqe)) {
                // Done with operation mark it as unused.
                self.op_list.items[idx] = .{};
                self.metric.active_op -= 1;
                self.next_free_op = idx;
                if (op.callback != null) op.ref.?.* = null;
            }
            if (op.callback) |callback| callback(self, op, cqe);
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

/// Number of unused submission queue entries
/// Matched liburing io_uring_sq_space_left
fn sqSpaceLeft(self: *Loop) u32 {
    return @as(u32, @intCast(self.ring.sq.sqes.len)) - self.ring.sq_ready();
}

fn ensureSqCapacity(self: *Loop, count: u32) SubmitError!void {
    assert(count <= self.ring.sq.sqes.len);
    while (self.sqSpaceLeft() < count) {
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
fn getOrCreateOp(self: *Loop) error{OutOfMemory}!struct { *Op, usize } {
    // Find existing free operation
    {
        const ops = self.op_list.items;
        // find unused op with higher index than the last one
        for (self.next_free_op..ops.len) |idx| {
            const op = &ops[idx];
            if (op.ref == null) return .{ op, idx };
        }
        // find unused from start of the list
        for (0..@min(self.next_free_op, ops.len)) |idx| {
            const op = &ops[idx];
            if (op.ref == null) return .{ op, idx };
        }
    }
    // Increase operations list
    try self.op_list.append(.{});
    const idx = self.op_list.items.len - 1;
    return .{ &self.op_list.items[idx], idx };
}

fn prepareOp(
    self: *Loop,
    ref: *?u32,
    callback: Op.Callback,
) error{OutOfMemory}!struct { *Op, usize } {
    const op, const idx = try self.getOrCreateOp();
    assert(ref.* == null);
    assert(op.ref == null);
    self.metric.active_op += 1;
    op.* = .{
        .ref = ref,
        .callback = callback,
    };
    ref.* = @intCast(idx);
    return .{ op, idx };
}

/// Get io_uring direct socket. If there are no free socket we will get:
/// error.FileTableOverflow.
pub fn socket(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!linux.fd_t) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    domain: u32,
    socket_type: u32,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref orelse return)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);
    _ = self.ring.socket_direct_alloc(user_data, domain, socket_type, 0, 0) catch unreachable;
}

/// error.AddressAlreadyInUse
pub fn listen(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!void) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    /// Lifetime has to be until completion is received
    addr: *std.net.Address,
    opt: std.net.Address.ListenOptions,
) PrepareError!void {
    try self.ensureSqCapacity(if (opt.reuse_address) 4 else 2);
    _, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) {} else |err| err,
            );
        }
    }.callback);

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
    sqe = self.ring.listen(user_data, fd, opt.kernel_backlog, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
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
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!void) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    addr: *std.net.Address,
    timeout: ?*linux.kernel_timespec,
) PrepareError!void {
    try self.ensureSqCapacity(2);
    _, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),

                if (success(cqe)) {} else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.connect(user_data, fd, &addr.any, addr.getOsSockLen()) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (timeout) |t| {
        sqe.flags |= linux.IOSQE_IO_LINK;
        sqe = self.ring.link_timeout(no_user_data, t, 0) catch unreachable;
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }
}

pub fn accept(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!linux.fd_t) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.accept_direct(user_data, fd, null, null, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Returns 0 on graceful shutdown.
///   error.ConnectionResetByPeer when remote host sends RST packet
/// Common syscall errors to handle:
///   error.OperationCanceled
///   error.InterruptedSystemCall
pub fn recv(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!u32) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer: []u8,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.recv(user_data, fd, .{ .buffer = buffer }, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn recvBufferGroup(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError![]u8) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer_group_id: u16,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    var op, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(loop: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            const ptr: *Parent = @alignCast(@fieldParentPtr(parent_field_name, op.ref.?));
            if (success(cqe)) {
                if (cqe.res == 0) return onComplete(ptr, &.{});
                var bg = loop.buffer_groups.items[op.args.recv.buffer_group_id];
                const buf = bg.get(cqe) catch unreachable;
                onComplete(ptr, buf);
                bg.put(cqe) catch unreachable;
                loop.metric.recv +%= 1;
            } else |err| {
                onComplete(ptr, err);
                switch (err) {
                    error.NoBufferSpaceAvailable => loop.metric.recv_no_buffer +%= 1,
                    else => {},
                }
            }
        }
    }.callback);
    op.args = .{ .recv = .{ .buffer_group_id = buffer_group_id } };

    var bg = self.buffer_groups.items[buffer_group_id];
    var sqe = bg.recv(user_data, fd, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Send on closed socket will return:
///   error.BrokenPipe - send on closed socket
///   error.ConnectionResetByPeer - send on forcefully closed socket (RST)
/// Common syscall errors to handle:
///   error.OperationCanceled
///   error.InterruptedSystemCall
pub fn send(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!u32) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer: []const u8,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.prepareOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.send(user_data, fd, buffer, linux.MSG.WAITALL | linux.MSG.NOSIGNAL) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Close file descriptor and cancel any pending operations on that fd.
pub fn close(self: *Loop, fd: linux.fd_t) SubmitError!void {
    if (fd < 0) return;
    try self.ensureSqCapacity(2);

    // close socket
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
    try self.ensureSqCapacity(1);
    var sqe = self.ring.cancel(no_user_data, idx, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Detach (don't call callback when completed) single operation by index and
/// cancel that operation if still active.
pub fn detach(self: *Loop, idx: usize) !void {
    const op = &self.op_list.items[idx];
    assert(op.ref != null);
    op.detach();
    try self.cancel(idx);
}

fn tickTimer(self: *Loop, ts: *linux.kernel_timespec) SubmitError!void {
    try self.ensureSqCapacity(1);
    _ = self.ring.timeout(timer_user_data, ts, 0, 0) catch unreachable;
}

pub fn addBufferGroup(
    self: *Loop,
    buffer_size: u32,
    buffers_count: u16,
) !u16 {
    const idx: u16 = @intCast(self.buffer_groups.items.len);
    try self.buffer_groups.ensureTotalCapacityPrecise(self.allocator, idx + 1);
    const bg = try linux.IoUring.BufferGroup.init(
        &self.ring,
        self.allocator,
        idx,
        buffer_size,
        buffers_count,
    );
    self.buffer_groups.appendAssumeCapacity(bg);
    return idx;
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
        op: ?u32 = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            assert(self.op == null);
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
        assert(ctx.op == null);
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        assert(ctx.op != null);
        try loop.tickNr(1);
        assert(ctx.op == null);
        try testing.expectEqual(1, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    { // success
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        try loop.tickNr(1);
        try testing.expectEqual(2, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    const used_fd = ctx.fd.?;
    { // fail no more fds
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
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
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        try loop.tickNr(1);
        try testing.expectEqual(4, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
}

test "ensure ensureSqCapacity pushes sqes to the kernel" {
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
        op: ?u32 = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            _ = self;
            _ = err_fd catch unreachable;
        }
    };
    var ctx1: Ctx = .{};
    var ctx2: Ctx = .{};
    var ctx3: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    // 2 entries but 3 prepared sqe
    // there was submit in ensureSqCapacity
    try loop.socket(Ctx, Ctx.onSocket, "op", &ctx1.op, domain, socket_type);
    try loop.socket(Ctx, Ctx.onSocket, "op", &ctx2.op, domain, socket_type);
    try loop.socket(Ctx, Ctx.onSocket, "op", &ctx3.op, domain, socket_type);
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
        op: ?u32 = null,

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
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        ctx.op = null;
    }
    try testing.expectEqual(ops_count, loop.op_list.items.len);
    loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type) catch |err| switch (err) {
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
        op: ?u32 = null,

        fn onListen(self: *Self, _err: anyerror!void) void {
            _ = _err catch |e| {
                self.err = e;
            };
        }
    };

    var ctx: Ctx = .{};
    var addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 0);

    _ = try loop.listen(Ctx, Ctx.onListen, "op", &ctx.op, 0xffff, &addr, .{ .reuse_address = true });
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
        listen_op: ?u32 = null,
        recv_op: ?u32 = null,

        fn start(self: *Self) !void {
            try self.loop.socket(Self, onSocket, "listen_op", &self.listen_op, self.addr.any.family, linux.SOCK.STREAM);
        }

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            const fd = err_fd catch unreachable;
            self.listen_fd = fd;
            self.loop.listen(
                Self,
                onListen,
                "listen_op",
                &self.listen_op,
                fd,
                &self.addr,
                .{ .reuse_address = true },
            ) catch unreachable;
        }

        fn onListen(self: *Self, maybe_err: anyerror!void) void {
            _ = maybe_err catch unreachable;
            self.loop.accept(Self, onAccept, "listen_op", &self.listen_op, self.listen_fd.?) catch unreachable;
        }

        fn onAccept(self: *Self, err_fd: anyerror!linux.fd_t) void {
            const fd = err_fd catch unreachable;
            self.conn_fd = fd;
            self.loop.recv(Self, onRecv, "recv_op", &self.recv_op, fd, self.buffer[self.buffer_pos..]) catch unreachable;
        }

        fn onRecv(self: *Self, err_n: anyerror!u32) void {
            const n = err_n catch unreachable;
            self.conn_count += 1;
            self.buffer_pos += n;
            self.loop.close(self.conn_fd.?) catch unreachable;
            self.conn_fd = null;
            self.loop.accept(Self, onAccept, "listen_op", &self.listen_op, self.listen_fd.?) catch unreachable;
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
    try testing.expectEqual(24, @sizeOf(Op));
}
