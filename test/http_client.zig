const std = @import("std");
const io = @import("lio");
const linux = std.os.linux;
const mem = std.mem;
const net = std.net;

const log = std.log.scoped(.main);
pub const std_options = std.Options{ .log_level = .debug };

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    const host = "www.google.com";
    const addr = try getAddress(gpa, host, 80);

    var loop = try io.Loop.init(gpa, .{
        .entries = 256,
        .fd_nr = 32,
    });
    defer loop.deinit();
    _ = try loop.addBufferGroup(4096, 1);

    var cli: Client = .init(&loop, addr, host);
    cli.connector.connect_timeout = 1000;
    cli.connector.connect();

    try loop.drain();
}

fn getAddress(allocator: mem.Allocator, host: []const u8, port: u16) !net.Address {
    const list = try net.getAddressList(allocator, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.UnknownHostName;
    return list.addrs[0];
}

const Client = struct {
    const Self = @This();

    loop: *io.Loop,
    connector: io.tcp.Connector(Self, "connector", onConnect, onConnectError),
    conn: io.tcp.Connection(Self, "conn", onRecv, onSend, onError),
    buffer: [64 * 1024]u8 = undefined,

    host: []const u8,

    pub fn init(loop: *io.Loop, addr: net.Address, host: []const u8) Self {
        return .{
            .loop = loop,
            .connector = .init(loop, addr),
            .conn = .init(loop, -1),
            .host = host,
        };
    }

    fn onConnect(self: *Self, fd: linux.fd_t) !void {
        self.conn.fd = fd;
        self.conn.recv_timeout = 1000;
        try self.get(self.host);
    }

    fn onConnectError(self: *Self, err: anyerror) void {
        if (io.tcp.isNetworkError(err)) {
            log.debug("reconnect {}", .{err});
            return self.connector.connect();
        }
        log.err("connector {}", .{err});
    }

    fn get(self: *Self, host: []const u8) !void {
        const request = try std.fmt.bufPrint(&self.buffer, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
        self.conn.send(request);
    }

    fn onSend(self: *Self) !void {
        self.conn.recv();
    }

    fn onRecv(self: *Self, data: []u8) !void {
        std.debug.print("{s}", .{data});
        self.conn.recv();
    }

    fn onError(self: *Self, err: anyerror) void {
        switch (err) {
            error.EndOfFile => return,
            error.TimerExpired => return,
            error.BrokenPipe, error.ConnectionResetByPeer => {
                log.debug("connection close {}", .{err});
            },
            else => {
                log.err("connection close {}", .{err});
            },
        }
        self.onConnectError(err);
    }
};
