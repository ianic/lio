const std = @import("std");
const tls = @import("tls");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;

const io = @import("root.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.tcp);

pub fn Connector(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onConnect: *const fn (*Parent, linux.fd_t, tls.nonblock.Connection, []const u8) anyerror!void,
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

        inline fn parent(self: *Self) *Parent {
            return @fieldParentPtr(parent_field_name, self);
        }

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

        pub fn connect(self: *Self) void {
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
                    self.parent(),
                    self.tcp_conn.fd,
                    tls.nonblock.Connection.init(self.tls_handshake.cipher().?),
                    self.recv_buf[0..self.recv_tail],
                ) catch |err| self.handleError(err);
                return;
            }

            self.tcp_conn.recv(self.recv_buf[self.recv_tail..]);
        }

        fn onSend(self: *Self, _: []const u8) !void {
            self.handshake();
        }

        fn onRecv(self: *Self, n: u32) !void {
            self.recv_tail += n;
            self.handshake();
        }

        fn onTcpConnectError(self: *Self, err: anyerror) void {
            _ = self;
            _ = err catch unreachable;
            // if (io.tcp.isNetworkError(err)) {
            //     log.debug("reconnect {}", .{err});
            //     return self.tcp.connect();
            // }
            // log.err("connector {}", .{err});
        }

        fn onClose(self: *Self, err: anyerror) void {
            if (err == error.EndOfFile) {
                self.handshake();
            } else {
                unreachable;
            }
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.tcp_connector.close() catch {};
            self.tcp_conn.close() catch {};
            _ = err catch unreachable;
        }
    };
}
