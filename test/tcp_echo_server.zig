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

    var ops = try gpa.alloc(io.Loop.Op, 2);
    defer gpa.free(ops);
    var loop = try io.Loop.init(.{
        .entries = 4096,
        .fd_nr = 1024,
        .op_list = ops,
    });
    defer loop.deinit();

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);
    var listener: Listener = .{
        .tcp = .init(&loop, addr),
        .allocator = gpa,
        .loop = &loop,
    };
    try listener.tcp.listen();

    var i: usize = 1;
    while (true) : (i +%= 1) {
        loop.runFor(1000) catch |err| {
            switch (err) {
                error.NoOperationsAvailable => {
                    log.debug("loop run {} ops.len: {}", .{ err, ops.len });
                    ops = try gpa.realloc(ops, ops.len * 2);
                    loop.op_list = ops;
                },
                // error.FileTableOverflow,
                else => {
                    log.err("loop run {}", .{err});
                    return err;
                },
            }
        };
        log.debug("run: {} bytes: {} MB: {}", .{ i, bytes, bytes / 1000_000 });
        bytes = 0;
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
        try conn.recv();
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

    fn recv(self: *Self) !void {
        try self.tcp.recv(&self.buffer);
    }

    pub fn onRecv(self: *Self, n: u32) !void {
        bytes += n;
        self.head = 0;
        self.tail = n;
        try self.tcp.send(self.buffer[self.head..self.tail]);
    }

    pub fn onSend(self: *Self, n: u32) !void {
        self.head += n;
        if (self.head == self.tail) {
            try self.recv();
        } else {
            try self.tcp.send(self.buffer[self.head..self.tail]);
        }
    }

    pub fn onClose(self: *Self) !void {
        self.parent.destroy(self);
    }
};
