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
    _ = try loop.addBufferGroup(64 * 1024, 8);

    buffer = try gpa.alloc(u8, 64 * 1024);
    rnd.bytes(buffer);
    defer gpa.free(buffer);

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);

    var clients: [24]Client = undefined;
    for (&clients, 0..) |*cli, no| {
        cli.* = Client.init(&loop, addr, no);
        cli.connector.connect();
    }

    var prev_metric = loop.metric;
    var i: usize = 1;
    while (true) : (i +%= 1) {
        try loop.runFor(10000);
        log.debug("run: {} recv: {} no buffers: {}", .{
            i,
            loop.metric.recv -% prev_metric.recv,
            loop.metric.recv_no_buffer -% prev_metric.recv_no_buffer,
        });
        prev_metric = loop.metric;
    }
}

const Client = struct {
    const Self = @This();

    loop: *io.Loop,
    connector: io.tcp.Connector(Self, "connector", onConnect, onConnectError),
    conn: io.tcp.Connection(Self, "conn", onRecv, onSend, onError),

    buffer: [64 * 1024]u8 = undefined,
    send_bytes: u32 = 0,
    recv_pos: u32 = 0,
    total_bytes: usize = 0,
    no: usize,

    pub fn init(loop: *io.Loop, addr: std.net.Address, no: usize) Self {
        return .{
            .loop = loop,
            .connector = .init(loop, addr),
            .conn = .init(loop, -1),
            .no = no,
        };
    }

    fn onConnect(self: *Self, fd: linux.fd_t) anyerror!void {
        self.total_bytes = 0;
        self.conn.fd = fd;
        self.echo();
    }

    fn onConnectError(self: *Self, err: anyerror) void {
        if (io.tcp.isNetworkError(err)) {
            //log.debug("reconnect {} on {}", .{ self.no, err });
            return self.connector.connect();
        }
        log.err("connector {}", .{err});
    }

    // Start echo cycle, send random bytes and expect to receive same bytes
    fn echo(self: *Self) void {
        if (self.total_bytes > 1024 * 1024 * 1024) {
            self.conn.close();
            self.onConnectError(error.EndOfFile);
            return;
        }

        self.recv_pos = 0;
        self.send_bytes = rnd.intRangeAtMost(u32, 16, 64 * 1024);
        self.conn.send(buffer[0..self.send_bytes]);
    }

    fn onSend(self: *Self) !void {
        self.conn.recv();
    }

    fn onRecv(self: *Self, data: []u8) !void {
        const n: u32 = @intCast(data.len);
        assert(std.mem.eql(u8, data, buffer[self.recv_pos..][0..n]));
        self.recv_pos += n;
        self.total_bytes += n;
        if (self.recv_pos == self.send_bytes) {
            self.echo();
        } else {
            self.conn.recv();
        }
    }

    fn onError(self: *Self, err: anyerror) void {
        switch (err) {
            error.EndOfFile => {
                // clean close
            },
            error.BrokenPipe, error.ConnectionResetByPeer => {
                log.debug("connection close {}", .{err});
            },
            error.TimerExpired, error.ConnectionTimedOut => {
                log.debug("connection recv timeout {}", .{err});
            },
            else => {
                log.err("connection error {}", .{err});
            },
        }
        self.onConnectError(err);
    }
};
