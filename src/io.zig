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
    flags: u32 = linux.IORING_SETUP_SQPOLL | linux.IORING_SETUP_SINGLE_ISSUER,
    /// Number of kernel registered file descriptors
    fd_nr: u16,
    /// Provided pool operations pool.
    /// Operation is submitted but not jet completed task; in kernel task.
    op_pool: OpPool,
};

fn peek_cqes(ring: *linux.IoUring, cqes: []linux.io_uring_cqe, wait_nr: u32) !u32 {
    const count = peek_cqes_ready(ring, cqes);
    if (count > 0) return count;
    if (ring.cq_ring_needs_flush() or wait_nr > 0) {
        _ = try ring.enter(0, wait_nr, linux.IORING_ENTER_GETEVENTS);
        return peek_cqes_ready(ring, cqes);
    }
    return 0;
}

fn peek_cqes_ready(ring: *linux.IoUring, cqes: []linux.io_uring_cqe) u32 {
    const ready = ring.cq_ready();
    const count = @min(cqes.len, ready);
    const head = ring.cq.head.* & ring.cq.mask;

    // before wrapping
    const n = @min(ring.cq.cqes.len - head, count);
    @memcpy(cqes[0..n], ring.cq.cqes[head..][0..n]);

    if (count > n) {
        // wrap self.cq.cqes
        const w = count - n;
        @memcpy(cqes[n..][0..w], ring.cq.cqes[0..w]);
    }

    //ring.cq_advance(count);
    return count;
}

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
        // TODO on callback error advance samo za one koji se obradio
        var cqes: [4]linux.io_uring_cqe = undefined;

        _ = try self.ring.submit();
        const n = try peek_cqes(&self.ring, &cqes, wait_nr);
        var advance_nr: u32 = 0;
        defer self.ring.cq_advance(advance_nr);

        //const n = try self.ring.copy_cqes(&cqes, wait_nr);
        for (cqes[0..n]) |cqe| {
            if (cqe.user_data == 0) {
                advance_nr += 1;
                continue;
            }
            const op: *Op = @ptrFromInt(cqe.user_data);
            try op.callback(op, self, cqe);
            // only advance if not error, will try next time same cqe
            advance_nr += 1;
        }
    }

    pub fn socket(
        self: *Loop,
        domain: u32,
        socket_type: u32,
        context: anytype,
        comptime onComplete: fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
    ) !*Op {
        // TODO ensure usused sqe capacity 1
        const op = try self.op_pool.create();
        _ = try self.ring.socket_direct_alloc(@intFromPtr(op), domain, socket_type, 0, 0);

        op.* = .{
            .context = context,
            .callback = struct {
                const Context = @TypeOf(context);
                fn complete(op_: *Op, _: *Loop, cqe: linux.io_uring_cqe) anyerror!void {
                    if (op_.context) |ptr| {
                        const ctx: Context = @alignCast(@ptrCast(ptr));
                        switch (cqe.err()) {
                            .SUCCESS => try onComplete(ctx, @intCast(cqe.res)),
                            else => |errno| try onComplete(ctx, errFromErrno(errno)),
                        }
                    }
                }
            }.complete,
        };
        return op;
    }
};

pub const Op = struct {
    context: ?*anyopaque,
    callback: *const fn (*Op, *Loop, linux.io_uring_cqe) anyerror!void,
};

test "socket" {
    var loop = try Loop.init(.{
        .entries = 16,
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
    const addr: std.net.Address = try .resolveIp("127.0.0.1", 0);
    const domain = addr.any.family;
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
        .entries = 16,
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
            _ = try err_fd;
            self.call_count += 1;
            return error.Dummy;

            // self.err = null;
            // self.fd = err_fd catch |err| brk: {
            //     self.err = err;
            //     break :brk null;
            // };
        }
    };
    var ctx: Ctx = .{};
    const addr: std.net.Address = try .resolveIp("127.0.0.1", 0);
    const domain = addr.any.family;
    const socket_type = linux.SOCK.STREAM;

    { // success
        _ = try loop.socket(domain, socket_type, &ctx, Ctx.onSocket);
        try testing.expectError(error.Dummy, loop.run(1));
        try testing.expectEqual(1, loop.ring.cq_ready());
        //try testing.expectEqual(1, ctx.call_count);
        //try testing.expect(ctx.fd != null);
        //try testing.expect(ctx.err == null);
    }
}
