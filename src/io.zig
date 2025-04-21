const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const linux = std.os.linux;
const fd_t = linux.fd_t;

const IoUring = linux.IoUring;

const errFromErrno = @import("errno.zig").toError;
const testing = std.testing;

pub const Loop = struct {
    const Self = @This();

    ring: IoUring,
    ops: std.heap.MemoryPool(Op) = undefined,

    pub fn init(entries: u16) !Self {
        return initWithFlags(entries, linux.IORING_SETUP_SQPOLL | linux.IORING_SETUP_SINGLE_ISSUER);
    }

    pub fn initWithFlags(entries: u16, flags: u32) !Self {
        return .{ .ring = try IoUring.init(entries, flags) };
    }

    pub fn deinit(self: *Self) void {
        self.ops.deinit();
        self.ring.deinit();
    }

    pub fn run(self: *Self, wait_nr: u32) !void {
        var cqes: [4]linux.io_uring_cqe = undefined;

        _ = try self.ring.submit();
        const n = try self.ring.copy_cqes(&cqes, wait_nr);
        for (cqes[0..n]) |cqe| {
            if (cqe.user_data == 0) continue;
            const op: *Op = @ptrFromInt(cqe.user_data);
            try op.callback(op, self, cqe);
        }
    }

    pub fn socket(
        self: *Loop,
        domain: u32,
        socket_type: u32,
        context: anytype,
        comptime onComplete: fn (@TypeOf(context), anyerror!fd_t) anyerror!void,
    ) !*Op {
        const op = try self.ops.create();
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
    var loop = try Loop.init(16);
    defer loop.deinit();

    try loop.ring.register_files_sparse(2);
    loop.ops = std.heap.MemoryPool(Op).init(testing.allocator);

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?fd_t = null,

        fn onSocket(self: *Self, err_fd: anyerror!fd_t) anyerror!void {
            self.call_count += 1;
            self.err = null;
            self.fd = err_fd catch |err| brk: {
                self.err = err;
                break :brk null;
            };
        }
    };
    var ctx: Ctx = .{};
    const addr: net.Address = try std.net.Address.resolveIp("127.0.0.1", 0);
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
