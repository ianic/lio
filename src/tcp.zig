const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;
const io = @import("root.zig");

pub const Listener = struct {
    const Self = @This();

    loop: *io.Loop,
    addr: std.net.Address,
    context: *anyopaque,
    onConnect: *const fn (*Self, anyerror!linux.fd_t) anyerror!void,
    fd: ?linux.fd_t = null, // listening socket
    op: ?*io.Loop.Op = null, // accept operation

    pub fn init(
        self: *Self,
        loop: *io.Loop,
        addr: std.net.Address,
        context: anytype,
        comptime onConnect: *const fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
    ) !void {
        self.* = .{
            .loop = loop,
            .addr = addr,
            .context = context,
            .onConnect = struct {
                const Context = @TypeOf(context);
                fn wrap(slf: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
                    const ctx: Context = @alignCast(@ptrCast(slf.context));
                    try onConnect(ctx, fd_err);
                }
            }.wrap,
        };
        _ = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, onSocket);
    }

    fn onSocket(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
        if (fd_err) |fd| {
            self.fd = fd;
            _ = self.loop.listen(fd, &self.addr, .{ .reuse_address = true }, self, onListen) catch |err| {
                return try self.onConnect(self, err);
            };
        } else |err| {
            try self.onConnect(self, err);
        }
    }

    fn onListen(self: *Self, _err: anyerror!void) anyerror!void {
        if (_err) |_| {
            try self.accept();
        } else |err| {
            try self.onConnect(self, err);
        }
    }

    fn onAccept(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
        self.op = null;
        try self.onConnect(self, fd_err);
        try self.accept();
    }

    fn accept(self: *Self) !void {
        self.op = self.loop.accept(self.fd.?, self, onAccept) catch |err| {
            return try self.onConnect(self, err);
        };
    }

    pub fn close(self: *Self) !void {
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
    var loop = try io.Loop.init(.{
        .entries = 16,
        .fd_nr = 2,
        .op_pool = io.Loop.OpPool.init(testing.allocator),
    });
    defer loop.deinit();

    const Server = struct {
        const Self = @This();
        conn_count: usize = 0,
        loop: *io.Loop,

        fn onConnect(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
            self.conn_count += 1;
            const conn_fd = try fd_err;
            try self.loop.close(conn_fd);
        }
    };
    var server: Server = .{ .loop = &loop };

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9899);
    var listener: io.tcp.Listener = undefined;
    //try listener.init(&loop, addr, &server, Server.onConnect);
    try loop.tcp.listen(&listener, addr, &server, Server.onConnect);

    var thr = try std.Thread.spawn(.{}, testConnect, .{addr});
    while (server.conn_count < 1024)
        try loop.tick();
    thr.join();

    try listener.close();
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
