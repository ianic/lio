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

    cwd = std.fs.cwd();

    var loop = try io.Loop.init(gpa, .{
        .entries = 4096,
        .fd_nr = 1024,
    });
    defer loop.deinit();

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9901);
    var listener: Listener = .{
        .tcp = .init(&loop, addr),
        .allocator = gpa,
        .loop = &loop,
    };
    listener.tcp.listen();
    defer listener.deinit();

    while (true) {
        try loop.tick();
    }
}

const Listener = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    tcp: io.tcp.Listener(Self, "tcp", onAccept, onError),
    total_bytes: usize = 0,
    connections: std.AutoArrayHashMapUnmanaged(*Connection, void) = .empty,

    fn onAccept(self: *Self, fd: posix.fd_t) anyerror!void {
        try self.connections.ensureUnusedCapacity(self.allocator, 1);
        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);
        conn.* = .init(self, fd);
        self.connections.putAssumeCapacity(conn, {});
        try conn.sendfile();
    }

    fn onError(_: *Self, err: anyerror) void {
        log.err("tcp listener error {}", .{err});
        // self.tcp.listen();
    }

    fn destroy(self: *Self, conn: *Connection) void {
        assert(self.connections.fetchSwapRemove(conn) != null);
        self.allocator.destroy(conn);
    }

    fn deinit(self: *Self) void {
        for (self.connections.keys()) |conn| {
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
    }
};

var cwd: std.fs.Dir = undefined;

const Connection = struct {
    const Self = @This();

    listener: *Listener,
    tcp: io.tcp.Connection(Self, "tcp", onRecv, onSend, onError),
    file: io.File(Self, "file", onOpen, onRead, onWrite, onError),

    buffer: [1024 * 64]u8 = undefined,
    recv_bytes: u32 = 0,

    pub fn init(listener: *Listener, fd: linux.fd_t) Self {
        return .{
            .listener = listener,
            .tcp = .init(listener.loop, fd),
            .file = .init(listener.loop, cwd.fd),
        };
    }

    fn sendfile(self: *Self) !void {
        try self.file.openRead("test/sendfile.zig");
    }

    fn onRecv(_: *Self, _: []u8) !void {
        unreachable;
    }

    fn onSend(_: *Self) !void {
        log.debug("onSend", .{});
        //unreachable;
    }

    fn onError(self: *Self, err: anyerror) void {
        log.err("connection close {}", .{err});
        self.listener.destroy(self);
    }

    fn onOpen(self: *Self) !void {
        self.tcp.sendfile(self.file.fd, 0, 1024 * 1024);
    }
    fn onRead(_: *Self, _: []u8) !void {}
    fn onWrite(_: *Self, _: []const u8) !void {}
};
