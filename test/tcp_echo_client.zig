const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("iox");
const mem = std.mem;

const log = std.log.scoped(.main);
pub const std_options = std.Options{ .log_level = .debug };

var prng = std.Random.DefaultPrng.init(0);
const rnd = prng.random();
var buffer: []u8 = &.{};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var loop = try io.Loop.init(.{
        .entries = 256,
        .fd_nr = 128,
        .op_list = io.Loop.OpList.init(gpa),
    });
    defer loop.deinit();

    buffer = try gpa.alloc(u8, 64 * 1024);
    rnd.bytes(buffer);
    defer gpa.free(buffer);

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);

    var conns: [24]Connection = undefined;
    for (&conns, 0..) |*conn, no| {
        try conn.init(&loop, addr, no);
    }

    while (true)
        try loop.tick();
}

const Connection = struct {
    const Self = @This();

    loop: *io.Loop,
    addr: std.net.Address,
    no: usize,
    connector: io.tcp.Connector = undefined,

    fd: linux.fd_t = 0,
    buffer: [64 * 1024]u8 = undefined,
    send_head: u32 = 0,
    send_tail: u32 = 0,
    recv_pos: u32 = 0,

    fn init(self: *Self, loop: *io.Loop, addr: std.net.Address, no: usize) !void {
        self.* = .{
            .loop = loop,
            .addr = addr,
            .no = no,
        };
        try self.connector.init(self.loop, self.addr, self, onConnect);
    }

    fn onConnect(self: *Self, fd_err: anyerror!posix.fd_t) anyerror!void {
        self.fd = fd_err catch |err| {
            switch (err) {
                error.ConnectionRefused,
                error.ConnectionResetByPeer,
                => {
                    return try self.connector.connect();
                },
                else => {
                    log.err("{} onConnect {}", .{ self.no, err });
                    return err;
                },
            }
        };
        log.debug("{} connected", .{self.no});
        try self.echo();
    }

    fn recv(self: *Self) !void {
        _ = try self.loop.recv(self.fd, &self.buffer, self, onRecv);
    }

    fn onRecv(self: *Self, n_err: anyerror!u32) anyerror!void {
        const n = n_err catch |err| {
            log.debug("{} recv {}", .{ self.no, err });
            switch (err) {
                error.ConnectionResetByPeer => {},
                error.OperationCanceled => {},
                error.SocketOperationOnNonsocket => {},
                else => log.err("{} recv {}", .{ self.no, err }),
            }
            return try self.reconnect();
        };
        if (n == 0) return try self.reconnect();

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
        // if (self.send_tail > 0)
        //     log.debug("echo {}", .{self.send_tail});
        self.recv_pos = 0;
        self.send_tail = rnd.intRangeAtMost(u32, 16, 64 * 1024);
        self.send_head = 0;
        try self.send();
    }

    fn send(self: *Self) !void {
        _ = try self.loop.send(self.fd, buffer[self.send_head..self.send_tail], self, onSend);
    }

    fn onSend(self: *Self, n_err: anyerror!u32) anyerror!void {
        self.send_head += n_err catch |err| {
            log.debug("{} send {}", .{ self.no, err });
            switch (err) {
                error.BrokenPipe, error.ConnectionResetByPeer => {},
                error.OperationCanceled => {},
                error.SocketOperationOnNonsocket => {},
                else => log.err("{} send {}", .{ self.no, err }),
            }
            return try self.reconnect();
        };

        if (self.send_head == self.send_tail) {
            try self.recv();
        } else {
            // can't happen because we are sending with msg.waitall in Loop.send
            log.err("{} short send", .{self.no});
            try self.send();
        }
    }

    fn reconnect(self: *Self) !void {
        log.debug("{} close", .{self.no});
        try self.loop.close(self.fd);
        try self.loop.detach(self);
        try self.connector.connect();
    }
};
