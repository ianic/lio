const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;
const io = @import("root.zig");
const tcp = @import("tcp.zig");

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
