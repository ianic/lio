const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const io = @import("root.zig");
const log = std.log.scoped(.tcp);

pub fn Connector(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onConnect: *const fn (*Parent, linux.fd_t) anyerror!void,
    comptime onError: *const fn (*Parent, err: anyerror) void,
) type {
    return struct {
        const Self = @This();

        loop: *io.Loop,
        addr: std.net.Address,
        connect_timeout: u32 = 10000, // in milliseconds
        fd: linux.fd_t = -1,
        connect_op: ?u32 = null,
        timeout_op: ?u32 = null,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, addr: std.net.Address) Self {
            return .{ .loop = loop, .addr = addr };
        }

        pub fn connect(self: *Self) void {
            assert(self.fd < 0);
            self.loop.socket(Self, socketComplete, "connect_op", &self.connect_op, self.addr.any.family, linux.SOCK.STREAM) catch |err| {
                return self.handleError(err);
            };
        }

        fn socketComplete(self: *Self, res: io.SyscallError!linux.fd_t) void {
            if (res) |fd| {
                self.fd = fd;
                self.loop.connect(Self, connectComplete, "connect_op", &self.connect_op, fd, &self.addr, null) catch |err| {
                    return self.handleError(err);
                };
                if (self.connect_timeout > 0) {
                    self.loop.setTimer(Self, onTimeout, "timeout_op", &self.timeout_op, self.connect_timeout) catch |err| {
                        return self.handleError(err);
                    };
                }
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.connect(),
                else => self.handleError(err),
            }
        }

        fn onTimeout(self: *Self) void {
            // TimerExpired TIME = 62
            // ConnectionTimedOut TIMEDOUT = 110
            assert(self.timeout_op == null);
            self.handleError(error.ConnectionTimedOut);
        }

        fn connectComplete(self: *Self, res: io.SyscallError!void) void {
            assert(self.timeout_op != null);
            if (self.timeout_op) |op| self.loop.removeTimer(op);
            assert(self.timeout_op == null);
            if (res) {
                onConnect(self.parent(), self.fd) catch |err| return self.handleError(err);
                self.fd = -2; // fd ownership transferred to the connection
            } else |err| {
                self.handleError(err);
            }
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.close() catch |e| {
                log.err("connector close {}", .{e});
                self.fd = -1;
            };
            onError(self.parent(), err);
        }

        pub fn close(self: *Self) !void {
            if (self.fd < 0) return;
            if (self.connect_op) |op| try self.loop.detach(op);
            if (self.timeout_op) |op| try self.loop.detach(op);
            try self.loop.close(self.fd);
            self.fd = -1;
        }
    };
}

/// Application can retry on network error
pub fn isNetworkError(err: anyerror) bool {
    return switch (err) {
        error.InterruptedSystemCall,
        error.OperationCanceled, // Connect timeout
        // TCP Connection read/write errors
        error.EndOfFile, // Clean connection close on read
        error.BrokenPipe,
        error.ConnectionResetByPeer, // ECONNRESET
        // Connect Network errors
        error.ConnectionRefused, // ECONNREFUSED
        error.NetworkIsUnreachable, // ENETUNREACH
        error.NoRouteToHost, // EHOSTUNREACH
        error.ConnectionTimedOut, // ETIMEDOUT
        => true,
        else => false,
    };
}

pub fn Listener(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onAccept: *const fn (*Parent, linux.fd_t) anyerror!void,
    comptime onError: *const fn (*Parent, anyerror) void,
) type {
    return struct {
        const Self = @This();

        loop: *io.Loop,
        addr: std.net.Address,
        fd: linux.fd_t = -1,
        listen_options: std.net.Address.ListenOptions = .{ .reuse_address = true },
        op: ?u32 = null,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, addr: std.net.Address) Self {
            return .{ .loop = loop, .addr = addr };
        }

        pub fn listen(self: *Self) void {
            assert(self.fd < 0);
            self.loop.socket(Self, socketComplete, "op", &self.op, self.addr.any.family, linux.SOCK.STREAM) catch |err| {
                return self.handleError(err);
            };
        }

        fn socketComplete(self: *Self, res: io.SyscallError!linux.fd_t) void {
            if (res) |fd| {
                self.fd = fd;
                self.loop.listen(Self, listenComplete, "op", &self.op, fd, &self.addr, self.listen_options) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.listen(),
                else => return self.handleError(err),
            }
        }

        fn listenComplete(self: *Self, res: io.SyscallError!void) void {
            if (res)
                self.accept()
            else |err| switch (err) {
                error.InterruptedSystemCall => self.listen(),
                else => return self.handleError(err),
            }
        }

        fn accept(self: *Self) void {
            self.loop.accept(Self, acceptComplete, "op", &self.op, self.fd) catch |err| {
                return self.handleError(err);
            };
        }

        fn acceptComplete(self: *Self, res: io.SyscallError!linux.fd_t) void {
            if (res) |fd|
                onAccept(self.parent(), fd) catch |err| {
                    return self.handleError(err);
                }
            else |err| switch (err) {
                error.InterruptedSystemCall => {},
                else => return self.handleError(err),
            }
            self.accept();
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.close() catch |e| {
                log.err("connector close {}", .{e});
                self.fd = -1;
            };
            onError(self.parent(), err);
        }

        pub fn close(self: *Self) !void {
            if (self.fd < 0) return;
            if (self.op) |op| try self.loop.detach(op);
            try self.loop.close(self.fd);
            self.fd = -1;
        }
    };
}

pub fn Connection(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onRecv: *const fn (*Parent, []u8) anyerror!void,
    comptime onSend: *const fn (*Parent, []const u8) anyerror!void,
    comptime onClose: *const fn (*Parent, anyerror) void,
) type {
    return struct {
        const Self = @This();

        loop: *io.Loop,
        fd: linux.fd_t = -1,
        buffer_group_id: u16 = 0,
        recv_timeout: u32 = 0,
        // Operation references used for cancelation on close
        send_op: ?u32 = null,
        recv_op: ?u32 = null,
        timeout_op: ?u32 = null,
        // Remember send/recv buffer so we can repeat operation on interrupt
        recv_buffer: []u8 = &.{},
        send_buffer: []const u8 = &.{},
        send_len: usize = 0,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, fd: linux.fd_t) Self {
            return .{
                .loop = loop,
                .fd = fd,
            };
        }

        pub fn send(self: *Self, buffer: []const u8) void {
            assert(self.send_buffer.len == 0);
            self.send_buffer = buffer;
            self.send_len = 0;
            self.sendSubmit();
        }

        fn sendSubmit(self: *Self) void {
            const buf = self.send_buffer[self.send_len..];
            self.loop.send(Self, sendComplete, "send_op", &self.send_op, self.fd, buf) catch |err| {
                return self.handleError(err);
            };
        }

        fn sendComplete(self: *Self, res: io.SyscallError!u32) void {
            if (res) |n| {
                self.send_len += n;
                if (self.send_len < self.send_buffer.len) {
                    // short send, send rest of the data
                    return self.sendSubmit();
                }
                const buf = self.send_buffer;
                self.send_buffer = &.{};
                onSend(self.parent(), buf) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.sendSubmit(),
                //error.OperationCanceled => unreachable,
                else => self.handleError(err),
            }
        }

        pub fn recvInto(self: *Self, buffer: []u8) void {
            self.loop.recv(Self, recvIntoComplete, "recv_op", &self.recv_op, self.fd, buffer) catch |err| {
                return self.handleError(err);
            };
            self.recv_buffer = buffer;
            self.recvTimeout();
        }

        fn recvIntoComplete(self: *Self, res: io.SyscallError!u32) void {
            if (self.timeout_op) |op| self.loop.removeTimer(op);
            if (res) |n| {
                const buf = self.recv_buffer[0..n];
                self.recv_buffer = &.{};
                if (n == 0) return self.handleError(error.EndOfFile); // clean close
                onRecv(self.parent(), buf) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.recvInto(self.recv_buffer),
                // error.OperationCanceled => unreachable,
                else => self.handleError(err),
            }
        }

        /// Receive using provided buffers from the self.buffer_group_id.
        pub fn recv(self: *Self) void {
            self.loop.recvBufferGroup(
                Self,
                recvComplete,
                "recv_op",
                &self.recv_op,
                self.fd,
                self.buffer_group_id,
            ) catch |err| {
                return self.handleError(err);
            };
            self.recvTimeout();
        }

        fn recvComplete(self: *Self, res: io.SyscallError![]u8) void {
            if (self.timeout_op) |op| self.loop.removeTimer(op);
            if (res) |buf| {
                if (buf.len == 0) return self.handleError(error.EndOfFile);
                onRecv(self.parent(), buf) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.NoBufferSpaceAvailable, error.InterruptedSystemCall => self.recv(),
                //error.OperationCanceled => unreachable,
                else => self.handleError(err),
            }
        }

        fn recvTimeout(self: *Self) void {
            if (self.recv_timeout > 0) {
                self.loop.setTimer(Self, onRecvTimeout, "timeout_op", &self.timeout_op, self.recv_timeout) catch |err| {
                    return self.handleError(err);
                };
            }
        }

        fn onRecvTimeout(self: *Self) void {
            self.handleError(error.TimerExpired);
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.close() catch |e| {
                log.err("tcp close {}", .{e});
                self.fd = -1;
            };
            onClose(self.parent(), err);
        }

        pub fn close(self: *Self) !void {
            if (self.fd < 0) return;
            if (self.recv_op) |op| try self.loop.detach(op);
            if (self.send_op) |op| try self.loop.detach(op);
            if (self.timeout_op) |op| try self.loop.detach(op);
            try self.loop.close(self.fd);
            self.fd = -1;
        }
    };
}

test "sizeOf" {
    const Client = struct {
        const Self = @This();

        connector: Connector(Self, "connector", onConnect, onConnectError),
        conn: Connection(Self, "conn", onRecv, onSend, onClose),

        fn onConnect(_: *Self, _: linux.fd_t) !void {}
        fn onConnectError(_: *Self, _: anyerror) void {}
        fn onSend(_: *Self, _: []const u8) !void {}
        fn onRecv(_: *Self, _: []u8) !void {}
        fn onClose(_: *Self, _: anyerror) void {}
    };

    try std.testing.expectEqual(232, @sizeOf(Client));
    try std.testing.expectEqual(144, @sizeOf(Connector(Client, "connector", Client.onConnect, Client.onConnectError)));
    try std.testing.expectEqual(88, @sizeOf(Connection(Client, "conn", Client.onRecv, Client.onSend, Client.onClose)));

    try std.testing.expectEqual(112, @sizeOf(std.net.Address));
    try std.testing.expectEqual(16, @sizeOf(linux.kernel_timespec));
}
