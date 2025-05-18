const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("lio");
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

    var loop = try io.Loop.init(gpa, .{
        .entries = 256,
        .fd_nr = 32,
    });
    defer loop.deinit();

    buffer = try gpa.alloc(u8, 64 * 1024);
    rnd.bytes(buffer);
    defer gpa.free(buffer);

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);

    var clients: [24]Connector = undefined;
    for (&clients, 0..) |*cli, no| {
        cli.* = Connector.init(&loop, addr, no);
        cli.tcp.connect();
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
        self.conn.echo();
    }

    pub fn onError(self: *Self, err: anyerror) void {
        if (io.tcp.isNetworkError(err)) {
            log.debug("reconnect {} on {}", .{ self.no, err });
            return self.tcp.connect();
        }
        log.err("connector {}", .{err});
    }
};

const Connection = struct {
    const Self = @This();

    parent: *Connector,
    tcp: io.tcp.Connection(Self, "tcp"),

    buffer: [64 * 1024]u8 = undefined,
    send_bytes: u32 = 0,
    recv_pos: u32 = 0,
    total_bytes: usize = 0,

    fn init(parent: *Connector, fd: linux.fd_t) Self {
        return .{
            .parent = parent,
            .tcp = .init(parent.loop, fd),
        };
    }

    // Start echo cycle, send random bytes and expect to receive same bytes
    fn echo(self: *Self) void {
        if (self.total_bytes > 1024 * 1024 * 1024) {
            self.tcp.close() catch unreachable;
            //self.parent.tcp.connect();
            self.parent.onError(error.EndOfFile);
            return;
        }

        self.recv_pos = 0;
        self.send_bytes = rnd.intRangeAtMost(u32, 16, 64 * 1024);
        self.tcp.send(buffer[0..self.send_bytes]);
    }

    pub fn onSend(self: *Self, _: []const u8) !void {
        self.tcp.recv(&self.buffer);
    }

    pub fn onRecv(self: *Self, n: u32) !void {
        assert(std.mem.eql(u8, self.buffer[0..n], buffer[self.recv_pos..][0..n]));
        self.recv_pos += n;
        self.total_bytes += n;
        if (self.recv_pos == self.send_bytes) {
            self.echo();
        } else {
            self.tcp.recv(&self.buffer);
        }
    }

    pub fn onClose(self: *Self, err: anyerror) void {
        switch (err) {
            error.EndOfFile => {},
            error.BrokenPipe, error.ConnectionResetByPeer => {
                log.debug("connection close {}", .{err});
            },
            else => {
                log.err("connection close {}", .{err});
            },
        }
        self.parent.onError(err);
    }
};
