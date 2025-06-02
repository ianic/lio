const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("lio");
const mem = std.mem;
const signal = @import("signal.zig");

const log = std.log.scoped(.main);
pub const std_options = std.Options{ .log_level = .debug };

pub fn main() !void {
    signal.setHandler();

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var loop = try io.Loop.init(gpa, .{
        .entries = 4096,
        .fd_nr = 1024,
        .flags = 0, //linux.IORING_SETUP_SINGLE_ISSUER, //| linux.IORING_SETUP_SQPOLL,
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
        loop.runFor(1000) catch |err| switch (err) {
            error.SignalInterrupt => {},
            else => return err,
        };
        if (signal.get()) |sig| switch (sig) {
            posix.SIG.TERM, posix.SIG.INT => break,
            else => {},
        };

        log.debug("run: {} bytes: {} MB: {} ops: {} active: {}", .{
            i,
            listener.total_bytes,
            listener.total_bytes / 1000_000,
            loop.metric.processed_op -% prev_metric.processed_op,
            loop.metric.active_op,
        });
        listener.total_bytes = 0;
        prev_metric = loop.metric;
    }

    log.debug("deinit", .{});
    listener.deinit();
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
        conn.recv();
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
        self.tcp.recvInto(&self.buffer);
    }

    fn onRecv(self: *Self, data: []u8) !void {
        const n: u32 = @intCast(data.len);
        self.listener.total_bytes += n;
        self.recv_bytes = n;
        self.tcp.send(self.buffer[0..self.recv_bytes]);
    }

    fn onSend(self: *Self, _: []const u8) !void {
        self.recv();
    }

    fn onClose(self: *Self, err: anyerror) void {
        log.err("connection close {}", .{err});
        self.listener.destroy(self);
    }
};
