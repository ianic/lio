const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("iox");
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
            bytes,
            bytes / 1000_000,
            loop.metric.processed_op -% prev_metric.processed_op,
            loop.metric.active_op,
        });
        bytes = 0;
        prev_metric = loop.metric;
    }

    try listener.close();
    try loop.drain();
}

var bytes: usize = 0;

const Listener = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    tcp: io.tcp.Listener(Self, "tcp"),

    pub fn onAccept(self: *Self, fd: posix.fd_t) !void {
        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);
        conn.* = .init(self, fd);
        conn.recv();
    }

    pub fn onError(self: *Self, err: anyerror) void {
        log.err("listener {}", .{err});
        self.tcp.listen();
    }

    fn destroy(self: *Self, conn: *Connection) void {
        self.allocator.destroy(conn);
    }
};

const Connection = struct {
    const Self = @This();

    parent: *Listener,
    tcp: io.tcp.Connection(Self, "tcp"),

    buffer: [1024 * 64]u8 = undefined,
    head: u32 = 0,
    tail: u32 = 0,

    pub fn init(parent: *Listener, fd: linux.fd_t) Self {
        return .{
            .parent = parent,
            .tcp = .init(parent.loop, fd),
        };
    }

    fn recv(self: *Self) void {
        self.tcp.recv(&self.buffer);
    }

    pub fn onRecv(self: *Self, n: u32) !void {
        bytes += n;
        self.head = 0;
        self.tail = n;
        self.tcp.send(self.buffer[self.head..self.tail]);
    }

    pub fn onSend(self: *Self, n: u32) !void {
        self.head += n;
        if (self.head == self.tail) {
            self.recv();
        } else {
            self.tcp.send(self.buffer[self.head..self.tail]);
        }
    }

    pub fn onClose(self: *Self, _: anyerror) void {
        self.parent.destroy(self);
    }
};
