const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("iox");
const mem = std.mem;

const log = std.log.scoped(.main);

var prng = std.Random.DefaultPrng.init(0);
const rnd = prng.random();
var buffer: []u8 = &.{};

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

    buffer = try gpa.alloc(u8, 64 * 1024);
    rnd.bytes(buffer);
    defer gpa.free(buffer);

    var conn: Connection = .{ .loop = &loop };
    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);
    var connector: io.tcp.Connector = undefined;
    try connector.init(&loop, addr, &conn, Connection.onConnect);

    while (true)
        try loop.tick();

    try connector.close();
    try loop.drain();
}

const Connection = struct {
    const Self = @This();

    loop: *io.Loop,
    fd: linux.fd_t = 0,
    buffer: [1024]u8 = undefined,
    send_head: u32 = 0,
    send_tail: u32 = 0,
    recv_pos: u32 = 0,
    recv_op: ?*io.Loop.Op = null,
    send_op: ?*io.Loop.Op = null,

    fn onConnect(self: *Self, fd_err: anyerror!posix.fd_t) anyerror!void {
        self.fd = try fd_err;
        try self.echo();
    }

    fn recv(self: *Self) !void {
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
        if (n == 0) return try self.close();

        assert(std.mem.eql(u8, self.buffer[0..n], buffer[self.recv_pos..][0..n]));
        self.recv_pos += n;
        if (self.recv_pos == self.send_tail) {
            try self.echo();
        } else {
            try self.recv();
        }
    }

    // start echo cycle, send random bytes and expect to receive same bytes
    fn echo(self: *Self) !void {
        if (self.send_tail > 0)
            log.debug("echo {}", .{self.send_tail});
        self.recv_pos = 0;
        self.send_tail = rnd.intRangeAtMost(u32, 16, 64 * 1024);
        self.send_head = 0;
        try self.send();
    }

    fn send(self: *Self) !void {
        self.send_op = try self.loop.send(self.fd, buffer[self.send_head..self.send_tail], self, onSend);
    }

    fn onSend(self: *Self, n_err: anyerror!u32) anyerror!void {
        self.send_op = null;
        self.send_head += n_err catch |err| {
            log.debug("send {}", .{err});
            switch (err) {
                error.BrokenPipe, error.ConnectionResetByPeer => {},
                error.OperationCanceled => {},
                error.SocketOperationOnNonsocket => {},
                else => log.err("send {}", .{err}),
            }
            return try self.close();
        };

        if (self.send_head == self.send_tail) {
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
    }
};
