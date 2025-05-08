const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const io = @import("root.zig");

pub fn Connector(comptime Parent: type, comptime parent_field_name: []const u8) type {
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
            return .{
                .loop = loop,
                .addr = addr,
            };
        }

        pub fn connect(self: *Self) !void {
            if (self.fd >= 0) try self.close();
            try self.connectSubmit();
        }

        fn connectSubmit(self: *Self) !void {
            assert(self.fd < 0);
            const wrap = struct {
                fn socketComplete(self_: *Self, res: io.SyscallError!linux.fd_t) anyerror!void {
                    if (res) |fd| {
                        self_.fd = fd;
                        self_.op = try self_.loop.connect(fd, &self_.addr, &self_.connect_timeout, self_, @This().connectComplete);
                    } else |err| switch (err) {
                        error.InterruptedSystemCall => try self_.connectSubmit(),
                        else => return err,
                    }
                }

                fn connectComplete(self_: *Self, res: io.SyscallError!void) anyerror!void {
                    if (res) {
                        try self_.parent().onConnect(self_.fd);
                        self_.fd = -2;
                    } else |err| switch (err) {
                        error.OperationCanceled, // connect timeout
                        error.InterruptedSystemCall,
                        // Network errors
                        error.ConnectionRefused, // ECONNREFUSED
                        error.NetworkIsUnreachable, // ENETUNREACH
                        error.NoRouteToHost, // EHOSTUNREACH
                        error.ConnectionTimedOut, // ETIMEDOUT
                        error.ConnectionResetByPeer, // ECONNRESET
                        => try self_.connect(),
                        else => return err,
                    }
                }
            };
            self.op = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, wrap.socketComplete);
        }

        pub fn close(self: *Self) !void {
            if (self.fd < 0) return;
            try self.loop.close(self.fd);
            self.fd = -1;
            try self.loop.detachOp(self.op, self);
        }
    };
}

pub fn Connection(comptime Parent: type, comptime parent_field_name: []const u8) type {
    return struct {
        const Self = @This();

        loop: *io.Loop,
        fd: linux.fd_t = -1,
        ops: [2]usize = .{ 0, 0 },

        // Remember used buffer so we can repeat operation on interrupt
        send_buffer: []const u8 = &.{},
        recv_buffer: []u8 = &.{},

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *io.Loop, fd: linux.fd_t) Self {
            return .{ .loop = loop, .fd = fd };
        }

        pub fn send(self: *Self, buffer: []const u8) !void {
            self.send_buffer = buffer;
            self.ops[0] = try self.loop.send(self.fd, buffer, self, sendComplete);
        }

        fn sendComplete(self: *Self, res: io.SyscallError!u32) anyerror!void {
            if (res) |n| {
                self.send_buffer = &.{};
                try self.parent().onSend(n);
            } else |err| switch (err) {
                error.BrokenPipe,
                error.ConnectionResetByPeer,
                => try self.close(),
                error.InterruptedSystemCall => try self.send(self.send_buffer),
                error.OperationCanceled => unreachable,
                else => return err,
            }
        }

        pub fn recv(self: *Self, buffer: []u8) !void {
            self.recv_buffer = buffer;
            self.ops[1] = try self.loop.recv(self.fd, buffer, self, recvComplete);
        }

        fn recvComplete(self: *Self, res: io.SyscallError!u32) anyerror!void {
            if (res) |n| {
                self.recv_buffer = &.{};
                if (n == 0) return try self.close();
                try self.parent().onRecv(n);
            } else |err| switch (err) {
                error.ConnectionResetByPeer => try self.close(),
                error.InterruptedSystemCall => try self.recv(self.recv_buffer),
                error.OperationCanceled => unreachable,
                else => return err,
            }
        }

        fn close(self: *Self) !void {
            try self.loop.close(self.fd);
            for (self.ops) |op| try self.loop.detachOp(op, self);
            try self.parent().onClose();
        }
    };
}
