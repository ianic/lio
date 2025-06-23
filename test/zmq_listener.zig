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
    connections: std.AutoArrayHashMapUnmanaged(*Connection, void) = .empty,
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

        conn.* = .init(self, fd);
        self.connections.putAssumeCapacity(conn, {});
        conn.upgrade(self.handshake);
    }

    fn onError(_: *Self, err: anyerror) void {
        log.err("tcp listener error {}", .{err});
        // self.tcp.listen();
    }

    fn destroy(self: *Self, conn: *Connection) void {
        assert(self.connections.fetchSwapRemove(conn) != null);
        conn.deinit();
        self.allocator.destroy(conn);
    }

    fn deinit(self: *Self) void {
        for (self.connections.keys()) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
        self.allocator.free(self.handshake);
    }
};

const Connection = struct {
    const Self = @This();

    allocator: mem.Allocator,
    listener: *Listener,
    tcp: io.tcp.Connection2(Self, "tcp"),
    recv_buf: io.UnusedDataBuffer,
    ping_op: ?u32 = null,
    heartbeat_interval: u32 = 5 * 1000, // send ping after
    recv_ops_count: usize = 0, // number of recv operations after ping is send
    pong_buf: [23]u8 = undefined,

    pub fn init(listener: *Listener, fd: linux.fd_t) Self {
        return .{
            .allocator = listener.allocator,
            .listener = listener,
            .tcp = .init(listener.loop, fd, .{ .onRecv = onHandshakeRecv, .onSend = onHandshakeSend, .onError = onError }),
            .recv_buf = .{},
        };
    }

    fn upgrade(self: *Self, handshake: []const u8) void {
        self.tcp.send(handshake);
    }

    fn onHandshakeSend(self: *Self) !void {
        self.tcp.recv_timeout = 10 * 1000;
        self.tcp.recv();
    }

    fn onHandshakeRecv(self: *Self, data: []u8) !void {
        var parser = zmq.protocol.Parser{ .buffer = try self.recv_buf.append(self.allocator, data) };
        const hs = try parser.handshake() orelse {
            try self.recv_buf.set(self.allocator, parser.unparsed());
            self.tcp.recv();
            return;
        };
        log.debug("connected: {}", .{hs.ready.socket_type});
        self.tcp.recv_timeout = 0;
        self.tcp.callbacks = .{ .onRecv = onRecv, .onSend = onSend, .onError = onError };
        try self.recv_buf.set(self.allocator, parser.unparsed());
        if (parser.unparsed().len > 0) {
            try self.onRecv(&.{});
        } else {
            self.tcp.recv();
        }
        self.setHeartbeatTimeout();
    }

    fn setHeartbeatTimeout(self: *Self) void {
        if (self.heartbeat_interval == 0) return;
        self.listener.loop.timeout(Self, onHeartbeatTimeout, "ping_op", &self.ping_op, self.heartbeat_interval) catch |err| {
            log.err("ping {}", .{err});
            self.tcp.close();
        };
        self.recv_ops_count = 0;
    }

    fn onHeartbeatTimeout(self: *Self) void {
        if (self.recv_ops_count == 0 and self.tcp.ready()) {
            log.debug("sending ping", .{});
            self.tcp.send(zmq.protocol.ping);
        }
        self.setHeartbeatTimeout();
    }

    fn onSend(self: *Self) !void {
        // TODO: da bi pozvao callback moram znati da li sam slao ping, subscribe ili neku drugu komandu
        // ovo je server strana pa nikada ne salje subscribe, ali salje ping koji nije application triggered
        _ = self;
    }

    fn onRecv(self: *Self, data: []u8) !void {
        self.recv_ops_count +|= 1;
        var parser = zmq.protocol.Parser{ .buffer = try self.recv_buf.append(self.allocator, data) };
        while (try parser.traffic()) |tr| {
            switch (tr) {
                .message => |msg| {
                    log.debug("onRecv message len {d}", .{msg.payload.len});
                    var iter = msg.frames();
                    while (iter.next()) |frm| {
                        log.debug("onRecv frame ({d}): '{s}'", .{ frm.len, frm.payload });
                    }
                },
                .command => |cmd| {
                    switch (cmd) {
                        .ping => |pi| {
                            // respond with pong
                            if (self.tcp.ready()) {
                                log.debug("onRecv ping ttl: {}, context: {x}", .{ pi.ttl, pi.context });
                                const pg = zmq.protocol.pong(&self.pong_buf, pi.context);
                                self.tcp.send(pg);
                            }
                        },
                        .pong => |pg| {
                            log.debug("onRecv pong context: {x}", .{pg.context});
                        },
                        .err => |reason| {
                            log.err("cmd close {s}", .{reason});
                            self.tcp.close();
                            return;
                        },
                        .subscribe => {},
                        .cancel => {},
                        .ready => {
                            // this command is valid only during handshake
                            self.tcp.close();
                        },
                    }
                },
            }
        }
        try self.recv_buf.set(self.allocator, parser.unparsed());
        self.tcp.recv();
    }

    fn onError(self: *Self, err: anyerror) void {
        switch (err) {
            error.TimerExpired => {
                if (self.tcp.send_op == null) {
                    self.tcp.send(zmq.protocol.ping);
                }
                return;
            },
            error.EndOfFile => {},
            else => {
                log.err("connection close {}", .{err});
            },
        }
        self.listener.destroy(self);
    }

    pub fn deinit(self: *Self) void {
        if (self.ping_op) |op| self.listener.loop.detach(op);
        self.recv_buf.deinit(self.allocator);
    }

    pub fn ready(self: *Self) bool {
        return self.tcp.ready();
    }
};
