const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;

const errFromErrno = @import("errno.zig").toError;
pub const OpList = std.ArrayList(Op);

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_SQPOLL,
    /// Number of kernel registered file descriptors
    fd_nr: u16,
    /// Provided pool operations pool.
    /// Operation is submitted but not jet completed task; in kernel task.
    op_list: OpList,
};

pub const Op = struct {
    ptr: ?*anyopaque = null,
    callback: *const fn (*Op, *Loop, linux.io_uring_cqe) anyerror!void = noopCallback,

    const noopCallback = struct {
        fn noop(_: *Op, _: *Loop, _: linux.io_uring_cqe) anyerror!void {}
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

ring: linux.IoUring,
op_list: OpList = undefined,
op_idx: usize = std.math.maxInt(usize),
metric: struct {
    active_op: usize = 0,
} = .{},

//TODO: add all tcp structs or remove
tcp: Tcp = .{},
pub const Tcp = struct {
    pub const Listener = @import("tcp.zig").Listener;
    pub fn listen(
        self: *@This(),
        listener: *Listener,
        addr: std.net.Address,
        context: anytype,
        comptime onConnect: *const fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
    ) !void {
        const loop: *Loop = @alignCast(@fieldParentPtr("tcp", self));
        try listener.init(loop, addr, context, onConnect);
    }
};

pub fn init(opt: Options) !Loop {
    var ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer ring.deinit();
    try ring.register_files_sparse(opt.fd_nr);
    return .{ .ring = ring, .op_list = opt.op_list };
}

pub fn deinit(self: *Loop) void {
    self.op_list.deinit();
    self.ring.deinit();
}

pub fn tickNr(self: *Loop, wait_nr: u32) !void {
    try self.processCompletions();
    _ = try self.ring.submit_and_wait(wait_nr);
    try self.processCompletions();
}

fn processCompletions(self: *Loop) !void {
    if (try self.processReadyCompletions()) _ = try self.processReadyCompletions();
}

/// Get completions and call operation callback for each completion.
/// Returns true in the case of overlapping ring.
///
/// In the case of the ring overlap there can be more completions at the start
/// of the ring. In that case need to peek two times first to get those from the
/// end of the cqes list and then to get those from the start of the list.
fn processReadyCompletions(self: *Loop) !bool {
    // peek list of ready cqes
    var ring = &self.ring;
    const ready = ring.cq_ready();
    if (ready == 0) return false;
    const head = ring.cq.head.* & ring.cq.mask;
    const tail = @min(ring.cq.cqes.len - head, ready);
    const cqes = ring.cq.cqes[head..][0..tail];

    // number of completed cqe's in this run
    var completed: u32 = 0;
    defer ring.cq_advance(completed);

    for (cqes) |cqe| {
        if (cqe.user_data == no_user_data) {
            // cqe without Op in userdata
            completed += 1;
            continue;
        }
        const op: *Op = &self.op_list.items[cqe.user_data];
        // std.debug.print("op: {} cqe: {}\n", .{ op, cqe });
        try op.callback(op, self, cqe);
        // Only advance if not error, will try next time same cqe in the
        // case of error.
        completed += 1;
        if (!flagMore(cqe)) {
            // Done with operation mark it as unused
            op.* = .{};
            self.metric.active_op -= 1;
        }
    }
    return cqes.len < ready;
}

pub fn tick(self: *Loop) !void {
    return self.tickNr(1);
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
pub fn sqSpaceLeft(self: *Loop) u32 {
    return @as(u32, @intCast(self.ring.sq.sqes.len)) - self.ring.sq_ready();
}

pub const RingSubmitError = error{
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

pub const SubmitError = RingSubmitError || error{OutOfMemory};

fn ensureSubmissionQueueCapacity(self: *Loop, count: u32) RingSubmitError!void {
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

/// Returns Op and index to that Op in op_list.items
fn getOp(self: *Loop) error{OutOfMemory}!struct { *Op, usize } {
    const op_count = self.op_list.items.len;
    if (self.metric.active_op < op_count) {
        // find unused op with higher index than ths last one
        for (self.op_idx + 1..op_count) |idx| {
            const op = &self.op_list.items[idx];
            if (op.ptr == null) {
                self.metric.active_op += 1;
                self.op_idx = idx;
                return .{ op, idx };
            }
        }
        // find unused from start of the list
        for (0..@min(self.op_idx + 1, op_count)) |idx| {
            const op = &self.op_list.items[idx];
            if (op.ptr == null) {
                self.metric.active_op += 1;
                self.op_idx = idx;
                return .{ op, idx };
            }
        }
    }
    try self.op_list.append(.{});
    const idx = self.op_list.items.len - 1;
    self.metric.active_op += 1;
    self.op_idx = idx;
    return .{ &self.op_list.items[idx], idx };
}

pub fn socket(
    self: *Loop,
    domain: u32,
    socket_type: u32,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
) SubmitError!usize {
    const op, const idx = try self.getOp();
    try self.ensureSubmissionQueueCapacity(1);
    _ = self.ring.socket_direct_alloc(idx, domain, socket_type, 0, 0) catch |err| switch (err) {
        error.SubmissionQueueFull => unreachable,
    };

    op.* = .{
        .ptr = context,
        .callback = struct {
            fn callback(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                const ctx: @TypeOf(context) = @alignCast(@ptrCast(op_.ptr orelse return));
                switch (cqe.err()) {
                    .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                    else => |errno| try onComplete(ctx, errFromErrno(errno)),
                }
            }
        }.callback,
    };
    return idx;
}

pub fn listen(
    self: *Loop,
    fd: linux.fd_t,
    /// Lifetime has to be until completion is received
    addr: *std.net.Address,
    opt: std.net.Address.ListenOptions,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), anyerror!void) anyerror!void,
) SubmitError!usize {
    const op, const idx = try self.getOp();
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
    sqe = self.ring.listen(idx, fd, opt.kernel_backlog, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    op.* = .{
        .ptr = context,
        .callback = struct {
            fn callback(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                const ctx: @TypeOf(context) = @alignCast(@ptrCast(op_.ptr orelse return));
                switch (cqe.err()) {
                    .SUCCESS => try onComplete(ctx, {}),
                    else => |errno| try onComplete(ctx, errFromErrno(errno)),
                }
            }
        }.callback,
    };
    return idx;
}

pub fn connect(
    self: *Loop,
    fd: linux.fd_t,
    addr: *std.net.Address,
    timeout: ?*linux.kernel_timespec,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), anyerror!void) anyerror!void,
) SubmitError!usize {
    const op, const idx = try self.getOp();
    try self.ensureSubmissionQueueCapacity(2);

    var sqe = self.ring.connect(idx, fd, &addr.any, addr.getOsSockLen()) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (timeout) |t| {
        sqe.flags |= linux.IOSQE_IO_LINK;
        sqe = self.ring.link_timeout(no_user_data, t, 0) catch unreachable;
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }

    op.* = .{
        .ptr = context,
        .callback = struct {
            fn callback(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                const ctx: @TypeOf(context) = @alignCast(@ptrCast(op_.ptr orelse return));
                switch (cqe.err()) {
                    .SUCCESS => try onComplete(ctx, {}),
                    else => |errno| try onComplete(ctx, errFromErrno(errno)),
                }
            }
        }.callback,
    };
    return idx;
}

pub fn accept(
    self: *Loop,
    fd: linux.fd_t,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
) SubmitError!usize {
    const op, const idx = try self.getOp();
    try self.ensureSubmissionQueueCapacity(1);

    var sqe = self.ring.accept_direct(idx, fd, null, null, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    op.* = .{
        .ptr = context,
        .callback = struct {
            fn callback(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                const ctx: @TypeOf(context) = @alignCast(@ptrCast(op_.ptr orelse return));
                switch (cqe.err()) {
                    .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                    else => |errno| try onComplete(ctx, errFromErrno(errno)),
                }
            }
        }.callback,
    };
    return idx;
}

pub fn recv(
    self: *Loop,
    fd: linux.fd_t,
    buffer: []u8,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), anyerror!u32) anyerror!void,
) SubmitError!usize {
    const op, const idx = try self.getOp();
    try self.ensureSubmissionQueueCapacity(1);

    var sqe = self.ring.recv(idx, fd, .{ .buffer = buffer }, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    op.* = .{
        .ptr = context,
        .callback = struct {
            fn callback(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                const ctx: @TypeOf(context) = @alignCast(@ptrCast(op_.ptr orelse return));
                switch (cqe.err()) {
                    .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                    else => |errno| try onComplete(ctx, errFromErrno(errno)),
                }
            }
        }.callback,
    };
    return idx;
}

pub fn send(
    self: *Loop,
    fd: linux.fd_t,
    buffer: []const u8,
    context: anytype,
    comptime onComplete: fn (@TypeOf(context), anyerror!u32) anyerror!void,
) SubmitError!usize {
    const op, const idx = try self.getOp();
    try self.ensureSubmissionQueueCapacity(1);

    var sqe = self.ring.send(idx, fd, buffer, linux.MSG.WAITALL | linux.MSG.NOSIGNAL) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;

    op.* = .{
        .ptr = context,
        .callback = struct {
            fn callback(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                const ctx: @TypeOf(context) = @alignCast(@ptrCast(op_.ptr orelse return));
                switch (cqe.err()) {
                    .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                    else => |errno| try onComplete(ctx, errFromErrno(errno)),
                }
            }
        }.callback,
    };
    return idx;
}

pub fn close(self: *Loop, fd: linux.fd_t) RingSubmitError!void {
    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.close_direct(no_user_data, @intCast(fd)) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

pub fn cancel(self: *Loop, idx: usize) RingSubmitError!void {
    try self.ensureSubmissionQueueCapacity(1);
    var sqe = self.ring.cancel(no_user_data, idx, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

pub fn detach(self: *Loop, op_idx: usize, ctx: *anyopaque) void {
    const op = &self.op_list.items[op_idx];
    if (op.ptr) |op_ctx| if (op_ctx == ctx) {
        op.detach(ctx);
    };
}

pub fn cancelOps(self: *Loop, ctx: *anyopaque) RingSubmitError!void {
    for (self.op_list.items, 0..) |*op, idx| if (op.ptr) |op_ctx| if (op_ctx == ctx) {
        op.detach(ctx);
        try self.cancel(idx);
    };
}

test "socket" {
    var loop = try Loop.init(.{
        .entries = 1,
        .fd_nr = 2,
        .op_list = OpList.init(testing.allocator),
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
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

test "error in callback, should not advance cq ring" {
    var loop = try Loop.init(.{
        .entries = 1,
        .fd_nr = 2,
        .op_list = OpList.init(testing.allocator),
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
            _ = try err_fd;
            self.call_count += 1;
            return error.OnSocketTestError;
        }
    };
    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    { // error in callback handler, cqe will be retried
        const op = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try testing.expectEqual(1, loop.metric.active_op);
        try testing.expectEqual(0, loop.ring.cq_ready());
        try testing.expectError(error.OnSocketTestError, loop.tickNr(1));
        try testing.expectEqual(1, loop.ring.cq_ready());
        try testing.expectEqual(1, ctx.call_count);
        loop.detach(op, &ctx);
    }
    { // retrying cqe, now succeeds
        try testing.expectEqual(1, loop.ring.cq_ready());
        try testing.expectEqual(1, loop.metric.active_op);
        try loop.tickNr(0);
        try testing.expectEqual(0, loop.metric.active_op);
        try testing.expectEqual(0, loop.ring.cq_ready());
        try testing.expectEqual(1, ctx.call_count);
    }
}

test "ensure unused sqes pushes sqes to the kernel" {
    var loop = try Loop.init(.{
        .entries = 2,
        .fd_nr = 2,
        .op_list = OpList.init(testing.allocator),
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
            _ = self;
            _ = try err_fd;
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
    var fba_buf: [@sizeOf(Op) * 10]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);

    var loop = try Loop.init(.{
        .entries = 2,
        .fd_nr = 2,
        .op_list = OpList.init(fba.allocator()),
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
            _ = self;
            _ = try err_fd;
        }
    };

    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    for (0..1024) |_| {
        _ = loop.socket(domain, socket_type, &ctx, Ctx.onSocket) catch |err| switch (err) {
            error.OutOfMemory => return,
            else => unreachable,
        };
    }
    unreachable;
}

test "listen (linked request) should return meaningful error" {
    var loop = try Loop.init(.{
        .entries = 4,
        .fd_nr = 2,
        .op_list = OpList.init(testing.allocator),
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        err: ?anyerror = null,

        fn onListen(self: *Self, _err: anyerror!void) anyerror!void {
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
    // echo -n one | nc -w0 localhost 9898 && echo -n two | nc -w0 localhost 9898 && echo -n three | nc -w0 localhost 9898 && echo -n four | nc -w0 localhost 9898

    var loop = try Loop.init(.{
        .entries = 16,
        .fd_nr = 2,
        .op_list = OpList.init(testing.allocator),
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

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
            const fd = try err_fd;
            self.listen_fd = fd;
            _ = try self.loop.listen(fd, &self.addr, .{ .reuse_address = true }, self, onListen);
        }

        fn onListen(self: *Self, maybe_err: anyerror!void) anyerror!void {
            _ = try maybe_err;
            _ = try self.loop.accept(self.listen_fd.?, self, onAccept);
        }

        fn onAccept(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
            const fd = try err_fd;
            self.conn_fd = fd;
            _ = try self.loop.recv(fd, self.buffer[self.buffer_pos..], self, onRecv);
        }

        fn onRecv(self: *Self, err_n: anyerror!u32) anyerror!void {
            const n = try err_n;
            self.conn_count += 1;
            self.buffer_pos += n;
            try self.loop.close(self.conn_fd.?);
            self.conn_fd = null;
            _ = try self.loop.accept(self.listen_fd.?, self, onAccept);
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
