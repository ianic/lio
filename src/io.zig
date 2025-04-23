const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;

const errFromErrno = @import("errno.zig").toError;
const OpPool = std.heap.MemoryPool(Op);

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_SQPOLL,
    /// Number of kernel registered file descriptors
    fd_nr: u16,
    /// Provided pool operations pool.
    /// Operation is submitted but not jet completed task; in kernel task.
    op_pool: OpPool,
};

pub const Loop = struct {
    const Self = @This();

    ring: linux.IoUring,
    op_pool: OpPool = undefined,

    pub fn init(opt: Options) !Self {
        var ring = try linux.IoUring.init(opt.entries, opt.flags);
        errdefer ring.deinit();
        try ring.register_files_sparse(opt.fd_nr);
        return .{ .ring = ring, .op_pool = opt.op_pool };
    }

    pub fn deinit(self: *Self) void {
        self.op_pool.deinit();
        self.ring.deinit();
    }

    pub fn run(self: *Self, wait_nr: u32) !void {
        // Push sqe's to the kernel
        _ = try self.ring.submit();

        var completed: u32 = 0; // number of completed cqe's in this run
        defer self.ring.cq_advance(completed);

        // Process all pending cqe's
        var res = try self.peekCqes(wait_nr);
        while (true) {
            for (res.cqes) |cqe| {
                if (cqe.user_data == 0) {
                    // cqe without Op in userdata
                    completed += 1;
                    continue;
                }
                const op: *Op = @ptrFromInt(cqe.user_data);
                try op.onComplete(op, self, cqe);
                // Only advance if not error, will try next time same cqe in the
                // case of error.
                completed += 1;
                if (!flagMore(cqe)) {
                    // Done with operation return it to the pool
                    self.op_pool.destroy(op);
                }
            }
            if (!res.hasMore()) break;
            res = try self.peekCqes(0);
        }
    }

    const PeekCqesResult = struct {
        cqes: []linux.io_uring_cqe,
        ready: u32,

        fn hasMore(self: @This()) bool {
            return self.ready > self.cqes.len;
        }
    };

    fn peekCqes(self: *Self, wait_nr: u32) !PeekCqesResult {
        const res = self.peekCqesReady();
        if (res.cqes.len > 0) return res;

        var ring = &self.ring;
        if (ring.cq_ring_needs_flush() or wait_nr > 0) {
            _ = try ring.enter(0, wait_nr, linux.IORING_ENTER_GETEVENTS);
            return self.peekCqesReady();
        }
        return .{ .cqes = &.{}, .ready = 0 };
    }

    fn peekCqesReady(self: *Self) PeekCqesResult {
        var ring = &self.ring;
        const ready = ring.cq_ready();
        const head = ring.cq.head.* & ring.cq.mask;

        const n = @min(ring.cq.cqes.len - head, ready);
        return .{ .cqes = ring.cq.cqes[head..][0..n], .ready = ready };
    }

    fn flagMore(cqe: linux.io_uring_cqe) bool {
        return cqe.flags & linux.IORING_CQE_F_MORE > 0;
    }

    /// Number of unused free submission queue entries
    pub fn unusedSqes(self: *Self) u32 {
        return @as(u32, @intCast(self.ring.sq.sqes.len)) - self.ring.sq_ready();
    }

    fn ensureUnusedSqes(self: *Self, count: u32) !void {
        assert(count <= self.ring.sq.sqes.len);
        while (self.unusedSqes() < count) {
            // TODO: is it safe to loop here
            _ = try self.ring.submit();
        }
    }

    pub fn socket(
        self: *Loop,
        domain: u32,
        socket_type: u32,
        context: anytype,
        comptime onComplete: fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
    ) !*Op {
        try self.ensureUnusedSqes(1);
        const op = try self.op_pool.create();
        _ = try self.ring.socket_direct_alloc(@intFromPtr(op), domain, socket_type, 0, 0);

        op.* = .{
            .context = context,
            .onComplete = struct {
                const Context = @TypeOf(context);
                fn complete(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                    const ctx: Context = @alignCast(@ptrCast(op_.context orelse return));
                    switch (cqe.err()) {
                        .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                        else => |errno| try onComplete(ctx, errFromErrno(errno)),
                    }
                }
            }.complete,
        };
        return op;
    }

    pub fn listen(
        self: *Loop,
        fd: linux.fd_t,
        addr: std.net.Address,
        opt: std.net.Address.ListenOptions,
        context: anytype,
        comptime onComplete: fn (@TypeOf(context), anyerror!void) anyerror!void,
    ) !*Op {
        try self.ensureUnusedSqes(if (opt.reuse_address) 4 else 2);
        const op = try self.op_pool.create();
        var sqe: *linux.io_uring_sqe = undefined;

        if (opt.reuse_address) {
            sqe = try self.ring.setsockopt(0, fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option);
            sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
            sqe = try self.ring.setsockopt(0, fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option);
            sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
        }
        sqe = try self.ring.bind(0, fd, &addr.any, addr.getOsSockLen(), 0);
        sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
        sqe = try self.ring.listen(@intFromPtr(op), fd, opt.kernel_backlog, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;

        op.* = .{
            .context = context,
            .onComplete = struct {
                const Context = @TypeOf(context);
                fn complete(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                    const ctx: Context = @alignCast(@ptrCast(op_.context orelse return));
                    switch (cqe.err()) {
                        .SUCCESS => try onComplete(ctx, {}),
                        else => |errno| try onComplete(ctx, errFromErrno(errno)),
                    }
                }
            }.complete,
        };
        return op;
    }

    pub fn accept(
        self: *Loop,
        fd: linux.fd_t,
        context: anytype,
        comptime onComplete: fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
    ) !*Op {
        try self.ensureUnusedSqes(1);
        const op = try self.op_pool.create();

        var sqe = try self.ring.accept_direct(@intFromPtr(op), fd, null, null, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;

        op.* = .{
            .context = context,
            .onComplete = struct {
                const Context = @TypeOf(context);
                fn complete(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                    const ctx: Context = @alignCast(@ptrCast(op_.context orelse return));
                    switch (cqe.err()) {
                        .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                        else => |errno| try onComplete(ctx, errFromErrno(errno)),
                    }
                }
            }.complete,
        };
        return op;
    }

    pub fn recv(
        self: *Loop,
        fd: linux.fd_t,
        buffer: []u8,
        context: anytype,
        comptime onComplete: fn (@TypeOf(context), anyerror!u32) anyerror!void,
    ) !*Op {
        try self.ensureUnusedSqes(1);
        const op = try self.op_pool.create();

        var sqe = try self.ring.recv(@intFromPtr(op), fd, .{ .buffer = buffer }, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;

        op.* = .{
            .context = context,
            .onComplete = struct {
                const Context = @TypeOf(context);
                fn complete(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                    const ctx: Context = @alignCast(@ptrCast(op_.context orelse return));
                    switch (cqe.err()) {
                        .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                        else => |errno| try onComplete(ctx, errFromErrno(errno)),
                    }
                }
            }.complete,
        };
        return op;
    }

    pub fn close(self: *Loop, fd: linux.fd_t) !void {
        try self.ensureUnusedSqes(1);
        var sqe = try self.ring.close_direct(0, @intCast(fd));
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }
};

const yes_value: u32 = 1;
const yes_socket_option = std.mem.asBytes(&yes_value);

pub const Op = struct {
    context: ?*anyopaque,
    onComplete: *const fn (*Op, *Loop, linux.io_uring_cqe) anyerror!void,

    pub fn detach(self: *Op, context: *anyopaque) void {
        assert(self.context.? == context);
        self.context = null;
    }
};

test "socket" {
    var loop = try Loop.init(.{
        .entries = 1,
        .fd_nr = 2,
        .op_pool = std.heap.MemoryPool(Op).init(testing.allocator),
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
        try loop.run(1);
        try testing.expectEqual(1, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    { // success
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.run(1);
        try testing.expectEqual(2, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    const used_fd = ctx.fd.?;
    { // fail no more fds
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.run(1);
        try testing.expectEqual(3, ctx.call_count);
        try testing.expect(ctx.err != null);
        try testing.expect(ctx.fd == null);
        try testing.expectEqual(ctx.err.?, error.FileTableOverflow);
    }
    { // return one used fd to the kernel
        _ = try loop.ring.close_direct(0, @intCast(used_fd));
        try loop.run(1);
    }
    { // success
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try loop.run(1);
        try testing.expectEqual(4, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
}

test "error in callback, should not advance cq ring" {
    var loop = try Loop.init(.{
        .entries = 1,
        .fd_nr = 2,
        .op_pool = OpPool.init(testing.allocator),
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
        try testing.expectEqual(0, loop.ring.cq_ready());
        try testing.expectError(error.OnSocketTestError, loop.run(1));
        try testing.expectEqual(1, loop.ring.cq_ready());
        try testing.expectEqual(1, ctx.call_count);
        op.detach(&ctx);
    }
    { // retrying cqe, now succeeds
        try testing.expect(loop.op_pool.free_list == null);
        try testing.expectEqual(1, loop.ring.cq_ready());
        try loop.run(0);
        try testing.expectEqual(0, loop.ring.cq_ready());
        try testing.expect(loop.op_pool.free_list != null);
        try testing.expectEqual(1, ctx.call_count);
    }
}

test "ensure unused sqes pushes sqes to the kernel" {
    var loop = try Loop.init(.{
        .entries = 2,
        .fd_nr = 2,
        .op_pool = OpPool.init(testing.allocator),
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

test "OutOfMemory on operation pool full" {
    var fba_buf: [@sizeOf(Op) * 10]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);

    var loop = try Loop.init(.{
        .entries = 2,
        .fd_nr = 2,
        .op_pool = std.heap.MemoryPool(Op).init(fba.allocator()),
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
test "tcp server" {
    // echo -n one | nc -w0 localhost 9898 && echo -n two | nc -w0 localhost 9898 && echo -n three | nc -w0 localhost 9898 && echo -n four | nc -w0 localhost 9898

    var loop = try Loop.init(.{
        .entries = 16,
        .fd_nr = 2,
        .op_pool = OpPool.init(testing.allocator),
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
        listen: bool = false,

        fn start(self: *Self) !void {
            _ = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, onSocket);
        }

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) anyerror!void {
            const fd = try err_fd;
            self.listen_fd = fd;
            _ = try self.loop.listen(fd, self.addr, .{ .reuse_address = true }, self, onListen);
        }

        fn onListen(self: *Self, maybe_err: anyerror!void) anyerror!void {
            _ = try maybe_err;
            self.listen = true;
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

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9898);
    var server: Server = .{
        .loop = &loop,
        .addr = addr,
    };

    try server.start();
    while (!server.listen) try loop.run(1);

    var thr = try std.Thread.spawn(.{}, testSend, .{addr});
    while (server.conn_count < 4) {
        try loop.run(1);
    }
    thr.join();

    try testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3 }, server.buffer[0..server.buffer_pos]);
}

fn testSend(addr: std.net.Address) void {
    for (0..4) |n| {
        var stream = std.net.tcpConnectToAddress(addr) catch unreachable;
        stream.writeAll(&[_]u8{@intCast(n)}) catch unreachable;
        stream.close();
    }
}
