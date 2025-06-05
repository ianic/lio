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
        tcp_conn: io.tcp.Connection(Self, "tcp_conn", onRecv, onSend, onClose),
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

        fn onSend(self: *Self, _: []const u8) !void {
            self.handshake();
        }

        fn onRecv(self: *Self, data: []u8) !void {
            self.recv_tail += data.len;
            self.handshake();
        }

        fn onTcpConnectError(self: *Self, err: anyerror) void {
            self.handleError(err);
        }

        fn onClose(self: *Self, err: anyerror) void {
            if (err == error.EndOfFile) return self.handshake();
            self.handleError(err);
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.tcp_connector.close() catch {};
            self.tcp_conn.close() catch {};
            onError(self.parent, err);
        }
    };
}

pub fn Connection(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onRecv: *const fn (*Parent, []const u8) anyerror!void,
    comptime onClose: *const fn (*Parent, anyerror) void,
) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        tcp: io.tcp.Connection(Self, "tcp", onTcpRecv, onTcpSend, onTcpClose),
        tls: tls.nonblock.Connection,
        recv_buf: io.UnusedDataBuffer = .{},

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
            const ciphertext = try self.allocator.alloc(u8, self.tls.encryptedLength(cleartext.len));
            errdefer self.allocator.free(ciphertext);
            const res = try self.tls.encrypt(cleartext, ciphertext);
            self.tcp.send(res.ciphertext);
            self.tcp.recv();
        }

        fn onTcpSend(self: *Self, ciphertext: []const u8) !void {
            self.allocator.free(ciphertext);
        }

        fn onTcpRecv(self: *Self, data: []u8) !void {
            const ciphertext = try self.recv_buf.append(self.allocator, data);

            const res = try self.tls.decrypt(ciphertext, ciphertext);
            if (res.cleartext.len > 0) {
                try onRecv(self.parent(), res.cleartext);
            }
            try self.recv_buf.set(self.allocator, res.unused_ciphertext);

            self.tcp.recv();
        }

        pub fn deinit(self: *Self) void {
            self.recv_buf.deinit(self.allocator);
        }

        pub fn close(self: *Self) !void {
            try self.tcp.close();
        }

        fn onTcpClose(self: *Self, err: anyerror) void {
            onClose(self.parent(), err);
        }
    };
}

test "sizeOf" {
    const Client = struct {
        const Self = @This();

        connector: *io.tls.Connector(Self, onConnect, onClose),
        conn: io.tls.Connection(Self, "conn", onRecv, onClose),

        fn onConnect(_: *Self, _: linux.fd_t, _: tls.nonblock.Connection, _: []const u8) !void {}
        fn onRecv(_: *Self, _: []const u8) !void {}
        fn onClose(_: *Self, _: anyerror) void {}
    };

    try std.testing.expectEqual(320, @sizeOf(Client));
    try std.testing.expectEqual(67584, @sizeOf(Connector(Client, Client.onConnect, Client.onClose)));
    try std.testing.expectEqual(312, @sizeOf(Connection(Client, "conn", Client.onRecv, Client.onClose)));
}
