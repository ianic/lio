const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const testing = std.testing;
const io = @import("root.zig");

pub const Connector = struct {
    const Self = @This();

    loop: *io.Loop,
    addr: std.net.Address,
    context: *anyopaque,
    callback: *const fn (*Self, anyerror!linux.fd_t) anyerror!void,
    fd: ?linux.fd_t = null, // connected socket
    op: ?*io.Loop.Op = null,
    connect_timeout: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },

    pub fn init(
        self: *Self,
        loop: *io.Loop,
        addr: std.net.Address,
        context: anytype,
        comptime callback: *const fn (@TypeOf(context), anyerror!linux.fd_t) anyerror!void,
    ) !void {
        self.* = .{
            .loop = loop,
            .addr = addr,
            .context = context,
            .callback = struct {
                const Context = @TypeOf(context);
                fn wrap(slf: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
                    const ctx: Context = @alignCast(@ptrCast(slf.context));
                    try callback(ctx, fd_err);
                }
            }.wrap,
        };
        try self.connect();
    }

    pub fn connect(self: *Self) !void {
        assert(self.op == null);
        if (self.fd) |fd| {
            self.op = try self.loop.connect(fd, &self.addr, &self.connect_timeout, self, onConnect);
        } else {
            self.op = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, onSocket);
        }
    }

    fn onSocket(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
        self.op = null;
        if (fd_err) |fd| {
            self.fd = fd;
            self.op = self.loop.connect(fd, &self.addr, &self.connect_timeout, self, onConnect) catch |err| {
                return try self.callback(self, err);
            };
        } else |err| {
            try self.callback(self, err);
        }
    }

    fn onConnect(self: *Self, _err: anyerror!void) anyerror!void {
        self.op = null;
        if (_err) |_| {
            try self.callback(self, self.fd.?);
        } else |err| {
            try self.callback(self, err);
        }
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

test "connector" {
    var loop = try io.Loop.init(.{
        .entries = 16,
        .fd_nr = 2,
        .op_pool = io.Loop.OpPool.init(testing.allocator),
    });
    defer loop.deinit();

    const Handler = struct {
        const Self = @This();
        connector: Connector = undefined,
        conn_count: usize = 0,

        fn onConnect(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
            if (fd_err) |_| {
                self.conn_count += 1;
                try self.connector.close();
            } else |err| switch (err) {
                error.ConnectionRefused => try self.connector.connect(),
                else => return err,
            }
        }
    };
    var handler: Handler = .{};
    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9890);
    try handler.connector.init(&loop, addr, &handler, Handler.onConnect);

    var thr = try std.Thread.spawn(.{}, testListen, .{addr});
    while (handler.conn_count < 1)
        try loop.tick();

    thr.join();
    try handler.connector.close();
    try loop.drain();
}

fn testListen(addr: std.net.Address) void {
    var server = addr.listen(.{ .reuse_address = true }) catch unreachable;
    var conn = server.accept() catch unreachable;
    conn.stream.close();
}
