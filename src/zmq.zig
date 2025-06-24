const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;
const io = @import("root.zig");
const tcp = @import("tcp.zig");
const log = std.log.scoped(.zmq);

pub const protocol = @import("zmq/protocol.zig");
pub const SocketType = protocol.SocketType;

pub fn Connector(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onConnect: *const fn (*Parent, linux.fd_t, protocol.Handshake, []const u8) anyerror!void,
    comptime onError: *const fn (*Parent, err: anyerror) void,
) type {
    return struct {
        const Self = @This();

        tcp_connector: io.tcp.Connector(Self, "tcp_connector", onTcpConnect, onTcpConnectError),
        tcp_conn: io.tcp.Connection(Self, "tcp_conn", onRecv, onSend, onTcpError),
        allocator: mem.Allocator,
        send_buf: []u8 = &.{},
        recv_buf: io.UnusedDataBuffer,
        socket_type: SocketType,
        identity: []const u8,

        pub fn init(
            allocator: mem.Allocator,
            loop: *io.Loop,
            addr: std.net.Address,
            socket_type: SocketType,
            identity: []const u8,
        ) Self {
            return .{
                .allocator = allocator,
                .tcp_connector = .init(loop, addr),
                .tcp_conn = .init(loop, -1),
                .socket_type = socket_type,
                .identity = identity,
                .recv_buf = .{},
            };
        }

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn connect(self: *Self) void {
            self.tcp_connector.connect();
        }

        pub fn onTcpConnect(self: *Self, fd: linux.fd_t) !void {
            self.tcp_conn.fd = fd;
            self.send_buf = try io.zmq.protocol.handshake(
                self.allocator,
                self.socket_type,
                self.identity,
            );
            self.tcp_conn.send(self.send_buf);
        }

        fn onSend(self: *Self) !void {
            self.allocator.free(self.send_buf);
            self.send_buf = &.{};
            self.tcp_conn.recv();
        }

        fn onRecv(self: *Self, data: []u8) !void {
            var zp = io.zmq.protocol.Parser{ .buffer = try self.recv_buf.append(self.allocator, data) };
            const hs = try zp.handshake() orelse {
                try self.recv_buf.set(self.allocator, zp.unparsed());
                self.tcp_conn.recv();
                return;
            };
            try onConnect(self.parent(), self.tcp_conn.fd, hs, zp.unparsed());
            self.recv_buf.deinit(self.allocator);
        }

        fn onTcpConnectError(self: *Self, err: anyerror) void {
            self.handleError(err);
        }

        fn onTcpError(self: *Self, err: anyerror) void {
            self.handleError(err);
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.tcp_connector.close();
            self.tcp_conn.close();
            self.recv_buf.deinit(self.allocator);
            onError(self.parent(), err);
        }
    };
}

pub fn Connection(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onConnect: *const fn (*Parent) anyerror!void,
    comptime onMessage: *const fn (*Parent, protocol.Message) anyerror!void,
    comptime onSubscribe: *const fn (*Parent, []const u8) anyerror!void,
    comptime onUnsubscribe: *const fn (*Parent, []const u8) anyerror!void,
    comptime onError: *const fn (*Parent, err: anyerror) void,
) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        loop: *io.Loop,
        tcp: io.tcp.Connection2(Self, "tcp"),
        recv_buf: io.UnusedDataBuffer,
        ping_op: ?u32 = null,
        /// timeout for handshake response
        handshake_timeout: u32 = 10 * 1000,
        /// send ping if there is no other activity during intervale
        heartbeat_interval: u32 = 5 * 1000,
        /// number of recv operations after ping is send
        recv_ops_count: usize = 0,
        /// buffer for building pong message (longest can be 23 bytes)
        pong_buf: [23]u8 = undefined,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(allocator: mem.Allocator, loop: *io.Loop, fd: linux.fd_t) Self {
            return .{
                .allocator = allocator,
                .loop = loop,
                .tcp = .init(loop, fd, .{ .onRecv = onHandshakeRecv, .onSend = onHandshakeSend, .onError = onTcpError }),
                .recv_buf = .{},
            };
        }

        pub fn upgrade(self: *Self, handshake: []const u8) void {
            self.tcp.send(handshake);
        }

        fn onHandshakeSend(self: *Self) !void {
            self.tcp.recv_timeout = self.handshake_timeout;
            self.tcp.recv();
        }

        fn onHandshakeRecv(self: *Self, data: []u8) !void {
            var parser = protocol.Parser{ .buffer = try self.recv_buf.append(self.allocator, data) };
            const hs = try parser.handshake() orelse {
                try self.recv_buf.set(self.allocator, parser.unparsed());
                self.tcp.recv();
                return;
            };
            _ = hs;
            // TODO check valid socket type

            self.tcp.recv_timeout = 0;
            self.tcp.callbacks = .{ .onRecv = onRecv, .onSend = onSend, .onError = onTcpError };
            try self.recv_buf.set(self.allocator, parser.unparsed());
            try onConnect(self.parent());

            if (parser.unparsed().len > 0) {
                try self.onRecv(&.{});
            } else {
                self.tcp.recv();
            }
            self.setHeartbeatTimeout();
        }

        fn setHeartbeatTimeout(self: *Self) void {
            if (self.heartbeat_interval == 0) return;
            self.loop.timeout(Self, onHeartbeatTimeout, "ping_op", &self.ping_op, self.heartbeat_interval) catch |err| {
                self.handleError(err);
            };
            self.recv_ops_count = 0;
        }

        fn onHeartbeatTimeout(self: *Self) void {
            if (self.recv_ops_count == 0 and self.tcp.ready()) {
                // log.debug("sending ping", .{});
                self.tcp.send(protocol.ping);
            }
            self.setHeartbeatTimeout();
        }

        fn onSend(self: *Self) !void {
            // TODO: da bi pozvao callback moram znati da li sam slao ping, subscribe ili neku drugu komandu
            // ovo je server strana pa nikada ne salje subscribe, ali salje ping koji nije application triggered
            _ = self;
        }

        fn onRecv(self: *Self, data: []u8) !void {
            self.recv_ops_count +|= 1;
            var parser = protocol.Parser{ .buffer = try self.recv_buf.append(self.allocator, data) };
            while (try parser.traffic()) |tr| {
                switch (tr) {
                    .message => |msg| {
                        try onMessage(self.parent(), msg);
                    },
                    .command => |cmd| {
                        switch (cmd) {
                            .ping => |pi| {
                                // respond with pong
                                if (self.tcp.ready()) {
                                    // log.debug("onRecv ping ttl: {}, context: {x}", .{ pi.ttl, pi.context });
                                    const pg = protocol.pong(&self.pong_buf, pi.context);
                                    self.tcp.send(pg);
                                }
                            },
                            .pong => |pg| {
                                _ = pg;
                                // log.debug("onRecv pong context: {x}", .{pg.context});
                            },
                            .err => |reason| {
                                log.err("cmd close {s}", .{reason});
                                self.handleError(error.ZmqErrorMessage);
                            },
                            .subscribe => |subscription| {
                                try onSubscribe(self.parent(), subscription);
                            },
                            .cancel => |subscription| {
                                try onUnsubscribe(self.parent(), subscription);
                            },
                            .ready => {
                                // this command is valid only during handshake
                                self.handleError(error.ZmqUnexpectedReady);
                            },
                        }
                    },
                }
            }
            try self.recv_buf.set(self.allocator, parser.unparsed());
            self.tcp.recv();
        }

        fn onTcpError(self: *Self, err: anyerror) void {
            self.handleError(err);
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.deinit();
            onError(self.parent(), err);
        }

        pub fn deinit(self: *Self) void {
            if (self.ping_op) |op| self.loop.detach(op);
            self.recv_buf.deinit(self.allocator);
        }

        pub fn ready(self: *Self) bool {
            return self.tcp.ready();
        }
    };
}
