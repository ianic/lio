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
        connect_timeout: linux.kernel_timespec = .{ .sec = 10, .nsec = 0 },
        fd: linux.fd_t = -1,
        op: usize = 0,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, addr: std.net.Address) Self {
            return .{ .loop = loop, .addr = addr };
        }

        pub fn connect(self: *Self) void {
            assert(self.fd < 0);
            self.op = self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, socketComplete) catch |err| {
                return self.handleError(err);
            };
        }

        fn socketComplete(self: *Self, res: io.SyscallError!linux.fd_t) void {
            if (res) |fd| {
                self.fd = fd;
                self.op = self.loop.connect(fd, &self.addr, &self.connect_timeout, self, connectComplete) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.connect(),
                else => self.handleError(err),
            }
        }

        fn connectComplete(self: *Self, res: io.SyscallError!void) void {
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
            try self.loop.detach(self.op, self);
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
        op: usize = 0,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, addr: std.net.Address) Self {
            return .{ .loop = loop, .addr = addr };
        }

        pub fn listen(self: *Self) void {
            assert(self.fd < 0);
            self.op = self.loop.socket(
                self.addr.any.family,
                linux.SOCK.STREAM,
                self,
                socketComplete,
            ) catch |err| {
                return self.handleError(err);
            };
        }

        fn socketComplete(self: *Self, res: io.SyscallError!linux.fd_t) void {
            if (res) |fd| {
                self.fd = fd;
                self.op = self.loop.listen(
                    fd,
                    &self.addr,
                    self.listen_options,
                    self,
                    listenComplete,
                ) catch |err| {
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
            self.op = self.loop.accept(self.fd, self, acceptComplete) catch |err| {
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
            try self.loop.detach(self.op, self);
            try self.loop.close(self.fd);
            self.fd = -1;
        }
    };
}

pub fn Connection(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onRecv: *const fn (*Parent, u32) anyerror!void,
    comptime onSend: *const fn (*Parent, []const u8) anyerror!void,
    comptime onClose: *const fn (*Parent, anyerror) void,
) type {
    return struct {
        const Self = @This();

        loop: *io.Loop,
        fd: linux.fd_t = -1,
        ops: [2]usize = .{ 0, 0 },

        // Remember used buffer so we can repeat operation on interrupt
        recv_buffer: []u8 = &.{},
        send_buffer: []const u8 = &.{},
        send_len: usize = 0,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, fd: linux.fd_t) Self {
            return .{ .loop = loop, .fd = fd };
        }

        pub fn send(self: *Self, buffer: []const u8) void {
            assert(self.send_buffer.len == 0);
            self.send_buffer = buffer;
            self.send_len = 0;
            self.sendSubmit();
        }

        fn sendSubmit(self: *Self) void {
            const buf = self.send_buffer[self.send_len..];
            self.ops[0] = self.loop.send(self.fd, buf, self, sendComplete) catch |err| {
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
                error.OperationCanceled => unreachable,
                else => self.handleError(err),
            }
        }

        pub fn recv(self: *Self, buffer: []u8) void {
            self.ops[1] = self.loop.recv(self.fd, buffer, self, recvComplete) catch |err| {
                return self.handleError(err);
            };
            self.recv_buffer = buffer;
        }

        fn recvComplete(self: *Self, res: io.SyscallError!u32) void {
            if (res) |n| {
                self.recv_buffer = &.{};
                if (n == 0) return self.handleError(error.EndOfFile); // clean close
                onRecv(self.parent(), n) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.recv(self.recv_buffer),
                error.OperationCanceled => unreachable,
                else => self.handleError(err),
            }
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
            for (self.ops) |op| try self.loop.detach(op, self);
            try self.loop.close(self.fd);
            self.fd = -1;
        }
    };
}

test "sizeOf" {
    const T = struct {};
    try std.testing.expectEqual(144, @sizeOf(Listener(T, "")));
    try std.testing.expectEqual(152, @sizeOf(Connector(T, "")));
}

const posix = std.posix;
const testing = std.testing;

test "operation is canceled on close" {
    var loop = try io.Loop.init(testing.allocator, .{
        .entries = 16,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Handler = struct {
        const Self = @This();
        conn_count: usize = 0,

        tcp: io.tcp.Listener(Self, "tcp"),

        pub fn onAccept(self: *Self, fd: posix.fd_t) !void {
            self.conn_count += 1;
            try self.tcp.loop.close(fd);
        }

        pub fn onError(_: *Self, _: anyerror) void {
            unreachable;
        }
    };
    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9991);
    var handler: Handler = .{ .tcp = .init(&loop, addr) };
    handler.tcp.listen();

    try loop.tickNr(1); // create socket
    try loop.tickNr(1); // listen

    // sync connect
    var stream = try std.net.tcpConnectToAddress(addr);
    defer stream.close();

    try loop.tickNr(1); // accept
    try testing.expectEqual(1, handler.conn_count);

    try handler.tcp.close();
    // there is active listen operation which will be canceled
    try testing.expectEqual(1, loop.metric.active_op);
    try loop.drain();
}
