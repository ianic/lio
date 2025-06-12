const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;
const io = @import("root.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.tls);

pub fn Connector(
    comptime Parent: type,
    comptime onConnect: *const fn (*Parent, linux.fd_t, tls.nonblock.Connection, []const u8) anyerror!void,
    comptime onError: *const fn (*Parent, err: anyerror) void,
) type {
    return struct {
        const Self = @This();

        tcp_connector: io.tcp.Connector(Self, "tcp_connector", onTcpConnect, onTcpConnectError),
        tcp_conn: io.tcp.Connection(Self, "tcp_conn", onRecv, onSend, onTcpError),
        tls_handshake: tls.nonblock.Client = undefined,
        config: tls.config.Client,

        recv_buf: [tls.max_ciphertext_record_len]u8 = undefined,
        recv_tail: usize = 0,
        send_buf: [tls.max_ciphertext_record_len]u8 = undefined,
        parent: *Parent = undefined,

        pub fn init(
            loop: *io.Loop,
            addr: std.net.Address,
            config: tls.config.Client,
        ) Self {
            return .{
                .config = config,
                .tcp_connector = .init(loop, addr),
                .tcp_conn = .init(loop, -1),
            };
        }

        pub fn connect(self: *Self, parent: *Parent) void {
            self.parent = parent;
            self.tcp_connector.connect();
        }

        pub fn onTcpConnect(self: *Self, fd: linux.fd_t) !void {
            self.tcp_conn.fd = fd;
            self.tls_handshake = .init(self.config);
            self.handshake();
        }

        fn handshake(self: *Self) void {
            const recv_buf = self.recv_buf[0..self.recv_tail];
            const res = self.tls_handshake.run(recv_buf, &self.send_buf) catch unreachable;

            // remove consumed part from recv_buf
            if (res.unused_recv.len == 0) {
                self.recv_tail = 0;
            } else if (res.unused_recv.len > 0) {
                @memmove(self.recv_buf[0..res.unused_recv.len], res.unused_recv);
                self.recv_tail = res.unused_recv.len;
            }

            if (res.send.len > 0) {
                self.tcp_conn.send(res.send);
                return;
            }
            if (self.tls_handshake.done()) {
                onConnect(
                    self.parent,
                    self.tcp_conn.fd,
                    tls.nonblock.Connection.init(self.tls_handshake.cipher().?),
                    self.recv_buf[0..self.recv_tail],
                ) catch |err| self.handleError(err);
                return;
            }

            self.tcp_conn.recvInto(self.recv_buf[self.recv_tail..]);
        }

        fn onSend(self: *Self) !void {
            self.handshake();
        }

        fn onRecv(self: *Self, data: []u8) !void {
            self.recv_tail += data.len;
            self.handshake();
        }

        fn onTcpConnectError(self: *Self, err: anyerror) void {
            self.handleError(err);
        }

        fn onTcpError(self: *Self, err: anyerror) void {
            if (err == error.EndOfFile) return self.handshake();
            self.handleError(err);
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.tcp_connector.close();
            self.tcp_conn.close();
            onError(self.parent, err);
        }
    };
}

pub fn Connection(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onSend: *const fn (*Parent) anyerror!void,
    comptime onRecv: *const fn (*Parent, []const u8) anyerror!void,
    comptime onError: *const fn (*Parent, anyerror) void,
) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        tcp: io.tcp.Connection(Self, "tcp", onTcpRecv, onTcpSend, onTcpError),
        tls: tls.nonblock.Connection,
        recv_buf: io.UnusedDataBuffer = .{},
        send_buf: []const u8 = &.{},

        pub fn init(
            allocator: mem.Allocator,
            loop: *io.Loop,
            fd: linux.fd_t,
            tls_conn: tls.nonblock.Connection,
            unused_handshake_buffer: []const u8,
        ) !Self {
            var self = Self{
                .allocator = allocator,
                .tcp = .init(loop, fd),
                .tls = tls_conn,
            };
            if (unused_handshake_buffer.len > 0)
                try self.recv_buf.set(allocator, unused_handshake_buffer);
            return self;
        }

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn send(self: *Self, cleartext: []const u8) !void {
            assert(self.send_buf.len == 0);
            const ciphertext = try self.allocator.alloc(u8, self.tls.encryptedLength(cleartext.len));
            errdefer self.allocator.free(ciphertext);
            const res = try self.tls.encrypt(cleartext, ciphertext);
            assert(res.ciphertext.len == ciphertext.len);
            self.send_buf = res.ciphertext;
            self.tcp.send(self.send_buf);
        }

        pub fn recv(self: *Self) void {
            self.tcp.recv();
        }

        fn onTcpSend(self: *Self) !void {
            self.allocator.free(self.send_buf);
            self.send_buf = &.{};
            try onSend(self.parent());
        }

        fn onTcpRecv(self: *Self, data: []u8) !void {
            const ciphertext = try self.recv_buf.append(self.allocator, data);

            const res = try self.tls.decrypt(ciphertext, ciphertext);
            if (res.cleartext.len > 0) {
                try onRecv(self.parent(), res.cleartext);
            } else {
                self.tcp.recv();
            }
            try self.recv_buf.set(self.allocator, res.unused_ciphertext);
        }

        pub fn deinit(self: *Self) void {
            self.recv_buf.deinit(self.allocator);
            self.allocator.free(self.send_buf);
        }

        pub fn close(self: *Self) !void {
            try self.tcp.close();
        }

        fn onTcpError(self: *Self, err: anyerror) void {
            onError(self.parent(), err);
        }
    };
}

test "sizeOf" {
    const Client = struct {
        const Self = @This();

        connector: *io.tls.Connector(Self, onConnect, onError),
        conn: io.tls.Connection(Self, "conn", onRecv, onError),

        fn onConnect(_: *Self, _: linux.fd_t, _: tls.nonblock.Connection, _: []const u8) !void {}
        fn onRecv(_: *Self, _: []const u8) !void {}
        fn onError(_: *Self, _: anyerror) void {}
    };

    try std.testing.expectEqual(336, @sizeOf(Client));
    try std.testing.expectEqual(67600, @sizeOf(Connector(Client, Client.onConnect, Client.onError)));
    try std.testing.expectEqual(328, @sizeOf(Connection(Client, "conn", Client.onRecv, Client.onError)));
}
