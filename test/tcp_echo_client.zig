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

    var ops: [64]io.Loop.Op = undefined;
    var loop = try io.Loop.init(.{
        .entries = 256,
        .fd_nr = 32,
        .op_list = &ops,
    });
    defer loop.deinit();

    buffer = try gpa.alloc(u8, 64 * 1024);
    rnd.bytes(buffer);
    defer gpa.free(buffer);

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);

    var clients: [24]Connector = undefined;
    for (&clients, 0..) |*cli, no| {
        cli.* = Connector.init(&loop, addr, no);
        try cli.tcp.connect();
    }

    while (true)
        try loop.tick();
}

const Connector = struct {
    const Self = @This();

    loop: *io.Loop,
    tcp: io.tcp.Connector(Self, "tcp"),
    conn: Connection = undefined,
    no: usize,

    pub fn init(loop: *io.Loop, addr: std.net.Address, no: usize) Self {
        return .{
            .loop = loop,
            .tcp = .init(loop, addr),
            .no = no,
        };
    }

    pub fn onConnect(self: *Self, fd: linux.fd_t) !void {
        self.conn = .init(self, fd);
        try self.conn.echo();
    }

    fn reconnect(self: *Self) !void {
        log.debug("{} reconnect", .{self.no});
        try self.tcp.connect();
    }
};

const Connection = struct {
    const Self = @This();

    parent: *Connector,
    tcp: io.tcp.Connection(Self, "tcp"),

    buffer: [64 * 1024]u8 = undefined,
    send_head: u32 = 0,
    send_tail: u32 = 0,
    recv_pos: u32 = 0,

    fn init(parent: *Connector, fd: linux.fd_t) Self {
        return .{
            .parent = parent,
            .tcp = .init(parent.loop, fd),
        };
    }

    // Start echo cycle, send random bytes and expect to receive same bytes
    fn echo(self: *Self) !void {
        self.recv_pos = 0;
        self.send_tail = rnd.intRangeAtMost(u32, 16, 64 * 1024);
        self.send_head = 0;
        try self.tcp.send(buffer[self.send_head..self.send_tail]);
    }

    pub fn onSend(self: *Self, n: u32) !void {
        self.send_head += n;
        if (self.send_head == self.send_tail) {
            try self.tcp.recv(&self.buffer);
        } else {
            // can't happen because we are sending with msg.waitall in Loop.send
            log.err("short send", .{});
            try self.tcp.send(buffer[self.send_head..self.send_tail]);
        }
    }

    pub fn onRecv(self: *Self, n: u32) !void {
        assert(std.mem.eql(u8, self.buffer[0..n], buffer[self.recv_pos..][0..n]));
        self.recv_pos += n;
        if (self.recv_pos == self.send_tail) {
            try self.echo();
        } else {
            try self.tcp.recv(&self.buffer);
        }
    }

    pub fn onClose(self: *Self) !void {
        try self.parent.reconnect();
    }
};
