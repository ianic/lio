const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const io = @import("root.zig");
const log = std.log.scoped(.tcp);

pub fn Connector(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onConnect: *const fn (*Parent, linux.fd_t) anyerror!void,
    comptime onError: *const fn (*Parent, anyerror) void,
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
                    self.loop.timeout(Self, onTimeout, "timeout_op", &self.timeout_op, self.connect_timeout) catch |err| {
                        return self.handleError(err);
                    };
                }
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.connect(),
                else => self.handleError(err),
            }
        }

        fn onTimeout(self: *Self) void {
            assert(self.timeout_op == null);
            self.handleError(error.ConnectionTimedOut);
        }

        fn connectComplete(self: *Self, res: io.SyscallError!void) void {
            assert(self.timeout_op != null);
            if (self.timeout_op) |op| self.loop.timeoutRemove(op);
            assert(self.timeout_op == null);
            if (res) {
                onConnect(self.parent(), self.fd) catch |err| return self.handleError(err);
                self.fd = -2; // fd ownership transferred to the connection
            } else |err| {
                self.handleError(err);
            }
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.close();
            onError(self.parent(), err);
        }

        pub fn close(self: *Self) void {
            if (self.fd < 0) return;
            if (self.connect_op) |op| self.loop.detach(op);
            if (self.timeout_op) |op| self.loop.detach(op);
            self.loop.close(self.fd) catch |err| {
                log.err("tcp connector close {}", .{err});
                return;
            };
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

pub fn isTimeoutError(err: anyerror) bool {
    return switch (err) {
        error.TimerExpired, // ETIME = 62
        error.ConnectionTimedOut, // ETIMEDOUT = 110
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
            self.close();
            onError(self.parent(), err);
        }

        pub fn close(self: *Self) void {
            if (self.fd < 0) return;
            if (self.op) |op| self.loop.detach(op);
            self.loop.close(self.fd) catch |err| {
                log.err("tcp listener close {}", .{err});
                return;
            };
            self.fd = -1;
        }
    };
}

pub fn Connection(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onRecv: *const fn (*Parent, []u8) anyerror!void,
    comptime onSend: *const fn (*Parent) anyerror!void,
    comptime onError: *const fn (*Parent, anyerror) void,
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
        send_args: ?SendArgs = null,
        sent_len: usize = 0,

        // Pipe file descriptors used in sendfile splices.
        // Created by sync system call on first use.
        pipe_fds: [2]linux.fd_t = .{ -1, -1 },

        pub const SendArgs = union(enum) {
            // simple data buffer send argument
            buffer: []const u8,
            // send file arguments
            file: struct {
                fd_in: linux.fd_t = -1,
                offset: u64 = 0,
                len: u32 = 0,
            },
        };

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, fd: linux.fd_t) Self {
            return .{
                .loop = loop,
                .fd = fd,
            };
        }

        pub fn send(self: *Self, data: []const u8) void {
            self.sendArgs(.{ .buffer = data });
        }

        pub fn sendfile(self: *Self, fd: linux.fd_t, offset: u64, len: u32) void {
            self.sendArgs(.{ .file = .{ .fd_in = fd, .offset = offset, .len = len } });
        }

        fn sendArgs(self: *Self, args: SendArgs) void {
            assert(self.send_args == null);
            self.send_args = args;
            self.sent_len = 0;
            self.sendSubmit();
        }

        fn sendSubmit(self: *Self) void {
            switch (self.send_args.?) {
                .buffer => |buf| {
                    self.loop.send(
                        Self,
                        sendComplete,
                        "send_op",
                        &self.send_op,
                        self.fd,
                        buf[self.sent_len..],
                    ) catch |err| {
                        return self.handleError(err);
                    };
                },
                .file => |arg| {
                    if (self.pipe_fds[0] == -1) {
                        self.pipe_fds = std.posix.pipe() catch |err| {
                            return self.handleError(err);
                        };
                    }

                    self.loop.sendfile(
                        Self,
                        sendComplete,
                        "send_op",
                        &self.send_op,
                        self.fd,
                        arg.fd_in,
                        self.pipe_fds,
                        arg.offset,
                        arg.len,
                    ) catch |err| {
                        return self.handleError(err);
                    };
                },
            }
        }

        fn sendComplete(self: *Self, res: io.SyscallError!u32) void {
            if (res) |n| {
                self.sent_len += n;
                const data_len = switch (self.send_args.?) {
                    .buffer => |buf| buf.len,
                    .file => |arg| arg.len,
                };
                if (self.sent_len < data_len) {
                    // short send, send rest of the data
                    return self.sendSubmit();
                }
                self.send_args = null;
                onSend(self.parent()) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.sendSubmit(),
                else => {
                    self.send_args = null;
                    self.handleError(err);
                },
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
            if (self.timeout_op) |op| self.loop.timeoutRemove(op);
            if (res) |n| {
                const buf = self.recv_buffer[0..n];
                self.recv_buffer = &.{};
                if (n == 0) return self.handleError(error.EndOfFile); // clean close
                onRecv(self.parent(), buf) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.recvInto(self.recv_buffer),
                else => {
                    self.recv_buffer = &.{};
                    self.handleError(err);
                },
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
            if (self.timeout_op) |op| self.loop.timeoutRemove(op);
            if (res) |buf| {
                if (buf.len == 0) return self.handleError(error.EndOfFile);
                onRecv(self.parent(), buf) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.NoBufferSpaceAvailable, error.InterruptedSystemCall => self.recv(),
                else => self.handleError(err),
            }
        }

        fn recvTimeout(self: *Self) void {
            if (self.recv_timeout > 0) {
                self.loop.timeout(Self, onRecvTimeout, "timeout_op", &self.timeout_op, self.recv_timeout) catch |err| {
                    return self.handleError(err);
                };
            }
        }

        fn onRecvTimeout(self: *Self) void {
            self.handleError(error.TimerExpired);
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.close();
            onError(self.parent(), err);
        }

        pub fn close(self: *Self) void {
            if (self.fd < 0) return;
            if (self.timeout_op) |op| self.loop.timeoutRemove(op);
            if (self.recv_op) |op| self.loop.detach(op);
            if (self.send_op) |op| self.loop.detach(op);
            if (self.pipe_fds[0] != -1) {
                if (self.loop.closePipe(self.pipe_fds)) {
                    self.pipe_fds = .{ -1, -1 };
                } else |err| {
                    log.err("tcp close pipe {}", .{err});
                }
            }
            if (self.loop.close(self.fd)) {
                self.fd = -1;
            } else |err| {
                log.err("tcp connection close {}", .{err});
            }
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
