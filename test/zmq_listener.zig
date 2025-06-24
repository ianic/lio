const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const net = std.net;
const signal = @import("signal.zig");
const io = @import("lio");
const zmq = io.zmq;

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
    });
    defer loop.deinit();
    _ = try loop.addBufferGroup(4 * 1024, 2);

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 5555);
    var listener = try Listener.init(gpa, &loop, addr, zmq.SocketType.router);
    listener.tcp.listen();
    defer listener.deinit();

    while (true) {
        loop.tick() catch |err| switch (err) {
            error.SignalInterrupt => {},
            else => return err,
        };
        if (signal.get()) |sig| switch (sig) {
            posix.SIG.TERM, posix.SIG.INT => break,
            else => {},
        };
    }
}

const Listener = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    tcp: io.tcp.Listener(Self, "tcp", onAccept, onError),
    connections: std.ArrayListUnmanaged(*Connection) = .empty,
    handshake: []const u8,

    fn init(allocator: mem.Allocator, loop: *io.Loop, addr: net.Address, socket_type: zmq.SocketType) !Self {
        return .{
            .allocator = allocator,
            .loop = loop,
            .tcp = .init(loop, addr),
            .handshake = try zmq.protocol.handshake(
                allocator,
                socket_type,
                &.{},
            ),
        };
    }

    fn onAccept(self: *Self, fd: posix.fd_t) anyerror!void {
        try self.connections.ensureUnusedCapacity(self.allocator, 1);
        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);

        //log.debug("onAccept connections: {}", .{self.connections.items.len});
        conn.* = .init(self, fd, self.connections.items.len);
        self.connections.appendAssumeCapacity(conn);
        conn.upgrade(self.handshake);
    }

    fn onError(self: *Self, err: anyerror) void {
        log.err("tcp listener error {}", .{err});
        self.tcp.listen();
    }

    fn destroy(self: *Self, conn: *Connection) void {
        // log.debug("destroy conn.idx: {}, connections: {}", .{ conn.idx, self.connections.items.len });
        assert(self.connections.swapRemove(conn.idx) == conn);
        if (conn.idx < self.connections.items.len) {
            // Update idx of the item which is swapped to the position of removed one
            self.connections.items[conn.idx].idx = conn.idx;
        }
        conn.deinit();
        self.allocator.destroy(conn);
    }

    fn deinit(self: *Self) void {
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
        self.allocator.free(self.handshake);
    }
};

const Connection = struct {
    const Self = @This();

    parent: *Listener,
    idx: usize, // index in parent.connections
    conn: zmq.Connection(Self, "conn", onConnect, onMessage, onSubscribe, onUnsubscribe, onError),

    pub fn init(parent: *Listener, fd: linux.fd_t, idx: usize) Self {
        return .{
            .parent = parent,
            .idx = idx,
            .conn = .init(parent.allocator, parent.loop, fd),
        };
    }

    fn upgrade(self: *Self, handshake: []const u8) void {
        self.conn.upgrade(handshake);
    }

    fn onConnect(self: *Self) !void {
        // log.debug("onConnect", .{});
        _ = self;
    }

    fn onMessage(self: *Self, msg: zmq.protocol.Message) !void {
        _ = self;
        _ = msg;

        // log.debug("onMessage message len {d}", .{msg.payload.len});
        // var iter = msg.frames();
        // while (iter.next()) |frm| {
        //     log.debug("  frame ({d}): '{s}'", .{ frm.len, frm.payload });
        // }
    }

    fn onSubscribe(self: *Self, subscription: []const u8) !void {
        _ = self;
        _ = subscription;
    }

    fn onUnsubscribe(self: *Self, subscription: []const u8) !void {
        _ = self;
        _ = subscription;
    }

    fn onError(self: *Self, err: anyerror) void {
        if (!io.tcp.isConnectionCloseError(err)) {
            log.err("connection {}", .{err});
        }
        self.parent.destroy(self);
    }

    fn deinit(self: *Self) void {
        self.conn.deinit();
    }
};
