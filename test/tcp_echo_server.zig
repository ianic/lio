const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("iox");
const mem = std.mem;

const log = std.log.scoped(.main);

// Connect with:
// $ nc -w0 localhost 9899
// Terminate with:
// $ pkill interrupt
// Signal:
// $ pkill -12 interrupt
pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var loop = try io.Loop.init(.{
        .entries = 16,
        .fd_nr = 16,
        .op_pool = io.Loop.OpPool.init(gpa),
    });
    defer loop.deinit();

    const Server = struct {
        const Self = @This();
        allocator: mem.Allocator,
        loop: *io.Loop,

        fn onConnect(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
            const fd = try fd_err;
            const conn = try self.allocator.create(Connection);
            conn.* = .{
                .allocator = self.allocator,
                .loop = self.loop,
                .fd = fd,
            };
            try conn.recv();
        }
    };
    var server: Server = .{
        .allocator = gpa,
        .loop = &loop,
    };
    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);
    var listener: io.tcp.Listener = undefined;
    try loop.tcp.listen(&listener, addr, &server, Server.onConnect);

    while (true)
        try loop.tick();

    try listener.close();
    try loop.drain();
}

const Connection = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    fd: linux.fd_t,
    buffer: [1024 * 64]u8 = undefined,
    head: u32 = 0,
    tail: u32 = 0,
    recv_op: ?*io.Loop.Op = null,
    send_op: ?*io.Loop.Op = null,

    fn recv(self: *Self) !void {
        self.head = 0;
        self.tail = 0;
        self.recv_op = try self.loop.recv(self.fd, &self.buffer, self, onRecv);
    }

    fn onRecv(self: *Self, n_err: anyerror!u32) anyerror!void {
        self.recv_op = null;
        const n = n_err catch |err| {
            log.debug("recv {}", .{err});
            switch (err) {
                error.ConnectionResetByPeer => {},
                error.OperationCanceled => {},
                error.SocketOperationOnNonsocket => {},
                else => log.err("recv {}", .{err}),
            }
            return try self.close();
        };
        log.debug("recv {}", .{n});
        if (n == 0) return try self.close();
        self.tail = n;
        try self.send();
    }

    fn send(self: *Self) !void {
        self.send_op = try self.loop.send(self.fd, self.buffer[self.head..self.tail], self, onSend);
    }

    fn onSend(self: *Self, n_err: anyerror!u32) anyerror!void {
        self.send_op = null;
        self.head += n_err catch |err| {
            log.debug("send {}", .{err});
            switch (err) {
                error.BrokenPipe, error.ConnectionResetByPeer => {},
                error.OperationCanceled => {},
                error.SocketOperationOnNonsocket => {},
                else => log.err("send {}", .{err}),
            }
            return try self.close();
        };

        if (self.head == self.tail) {
            try self.recv();
        } else {
            try self.send();
        }
    }

    fn close(self: *Self) !void {
        if (self.send_op) |op| {
            try self.loop.cancel(op);
            op.detach(self);
            self.send_op = null;
        }
        if (self.recv_op) |op| {
            try self.loop.cancel(op);
            op.detach(self);
            self.recv_op = null;
        }
        try self.loop.close(self.fd);
        self.allocator.destroy(self);
    }
};
