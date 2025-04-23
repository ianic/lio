const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;

const Loop = @import("Loop.zig");

pub const Listener = struct {
    const Self = @This();
    const Callback = *const fn (*anyopaque, anyerror!linux.fd_t) anyerror!void;

    loop: *Loop,
    addr: std.net.Address,
    ptr: ?*anyopaque = null,
    callback: Callback = undefined,
    fd: ?linux.fd_t = null, // listening socket
    op: ?*Loop.Op = null, // accept operation

    pub fn init(loop: *Loop, addr: std.net.Address) Self {
        return .{ .loop = loop, .addr = addr };
    }

    pub fn listen(self: *Self, ptr: *anyopaque, callback: Callback) !void {
        self.ptr = ptr;
        self.callback = callback;
        _ = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, onSocket);
    }

    fn onSocket(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
        if (fd_err) |fd| {
            self.fd = fd;
            _ = self.loop.listen(fd, self.addr, .{ .reuse_address = true }, self, onListen) catch |err| {
                return try self.callback(self.ptr.?, err);
            };
        } else |err| {
            try self.callback(self.ptr.?, err);
        }
    }

    fn onListen(self: *Self, _err: anyerror!void) anyerror!void {
        if (_err) |_| {
            try self.accept();
        } else |err| {
            try self.callback(self.ptr.?, err);
        }
    }

    fn onAccept(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
        self.op = null;
        try self.callback(self.ptr.?, fd_err);
        try self.accept();
    }

    fn accept(self: *Self) !void {
        self.op = self.loop.accept(self.fd.?, self, onAccept) catch |err| {
            return try self.callback(self.ptr.?, err);
        };
    }

    pub fn deinit(self: *Self) !void {
        if (self.fd) |fd| {
            _ = try self.loop.close(fd);
            self.fd = null;
        }
        if (self.op) |op| {
            try self.loop.cancel(op);
            op.detach(self);
            self.op = null;
        }
    }
};

test "connect to listener" {
    var loop = try Loop.init(.{
        .entries = 16,
        .fd_nr = 2,
        .op_pool = Loop.OpPool.init(testing.allocator),
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        conn_count: usize = 0,
        loop: *Loop,

        fn onAccept(ptr: *anyopaque, fd_err: anyerror!linux.fd_t) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            self.conn_count += 1;
            if (fd_err) |fd| {
                // std.debug.print("onAccept {} {}\n", .{ fd, self.conn_count });
                try self.loop.close(fd);
            } else |err| return err;
        }
    };
    var ctx: Ctx = .{ .loop = &loop };

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9899);
    var server = Listener.init(&loop, addr);
    try server.listen(&ctx, Ctx.onAccept);

    var thr = try std.Thread.spawn(.{}, testConnect, .{addr});
    while (ctx.conn_count < 1024)
        try loop.tick();
    thr.join();

    try server.deinit();
    try loop.drain();
}

fn testConnect(addr: std.net.Address) void {
    var conn_count: usize = 0;
    while (true) {
        var stream = std.net.tcpConnectToAddress(addr) catch |err| switch (err) {
            error.ConnectionRefused => continue,
            else => unreachable,
        };
        stream.close();
        conn_count += 1;
        if (conn_count >= 1024) break;
    }
}
