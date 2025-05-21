const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("lio");
const mem = std.mem;

const log = std.log.scoped(.main);
pub const std_options = std.Options{ .log_level = .debug };

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var loop = try io.Loop.init(gpa, .{
        .entries = 4096,
        .fd_nr = 1024,
    });
    defer loop.deinit();

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);
    var listener: Listener = .{
        .tcp = .init(&loop, addr),
        .allocator = gpa,
        .loop = &loop,
    };
    listener.tcp.listen();

    var prev_metric = loop.metric;
    var i: usize = 1;
    while (true) : (i +%= 1) {
        try loop.runFor(1000);
        log.debug("run: {} bytes: {} MB: {} ops: {} active: {}", .{
            i,
            total_bytes,
            total_bytes / 1000_000,
            loop.metric.processed_op -% prev_metric.processed_op,
            loop.metric.active_op,
        });
        total_bytes = 0;
        prev_metric = loop.metric;
    }

    try listener.close();
    try loop.drain();
}

var total_bytes: usize = 0;

const Listener = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    tcp: io.tcp.Listener(Self, "tcp", onAccept, onError),

    fn onAccept(self: *Self, fd: posix.fd_t) anyerror!void {
        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);
        conn.* = .init(self, fd);
        conn.recv();
    }

    fn onError(self: *Self, err: anyerror) void {
        log.err("listener {}", .{err});
        self.tcp.listen();
    }

    fn destroy(self: *Self, conn: *Connection) void {
        self.allocator.destroy(conn);
    }
};

const Connection = struct {
    const Self = @This();

    listener: *Listener,
    tcp: io.tcp.Connection(Self, "tcp", onRecv, onSend, onClose),

    buffer: [1024 * 64]u8 = undefined,
    recv_bytes: u32 = 0,

    pub fn init(listener: *Listener, fd: linux.fd_t) Self {
        return .{
            .listener = listener,
            .tcp = .init(listener.loop, fd),
        };
    }

    fn recv(self: *Self) void {
        self.tcp.recv(&self.buffer);
    }

    fn onRecv(self: *Self, n: u32) !void {
        total_bytes += n;
        self.recv_bytes = n;
        self.tcp.send(self.buffer[0..self.recv_bytes]);
    }

    fn onSend(self: *Self, _: []const u8) !void {
        self.recv();
    }

    fn onClose(self: *Self, _: anyerror) void {
        self.listener.destroy(self);
    }
};
