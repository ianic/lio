const std = @import("std");
const io = @import("lio");
const tls = @import("tls");
const linux = std.os.linux;
const mem = std.mem;
const net = std.net;
const assert = std.debug.assert;

const log = std.log.scoped(.main);
pub const std_options = std.Options{ .log_level = .debug };

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    //const host = "www.google.com";
    const host = "www.monitor.hr";
    const addr = try getAddress(gpa, host, 443);

    // tls config
    var root_ca = try tls.config.cert.fromSystem(gpa);
    defer root_ca.deinit(gpa);
    const config: tls.config.Client = .{
        .host = host,
        .root_ca = root_ca,
    };

    var loop = try io.Loop.init(gpa, .{
        .entries = 256,
        .fd_nr = 32,
    });
    defer loop.deinit();
    _ = try loop.addBufferGroup(4096, 1);

    var cli = try Client.init(gpa, &loop, addr, config, host);
    cli.connect();

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
    const Connector = io.tls.Connector(Self, onConnect, onConnectError);

    allocator: mem.Allocator,
    loop: *io.Loop,
    connector: *Connector,
    conn: io.tls.Connection(Self, "conn", onRecv, onClose),
    host: []const u8,

    pub fn init(
        allocator: mem.Allocator,
        loop: *io.Loop,
        addr: net.Address,
        config: tls.config.Client,
        host: []const u8,
    ) !Self {
        const connector = try allocator.create(Connector);
        connector.* = .init(loop, addr, config);
        return .{
            .allocator = allocator,
            .loop = loop,
            .connector = connector,
            .host = host,
            .conn = undefined,
        };
    }

    pub fn connect(self: *Self) void {
        self.connector.connect(self);
    }

    fn onConnect(
        self: *Self,
        fd: linux.fd_t,
        tls_conn: tls.nonblock.Connection,
        recv_buf: []const u8,
    ) !void {
        self.conn = try .init(self.allocator, self.loop, fd, tls_conn, recv_buf);
        self.conn.tcp.recv_timeout = 1000;
        try self.get(self.host);
        self.allocator.destroy(self.connector);
    }

    fn get(self: *Self, host: []const u8) !void {
        var buffer: [256]u8 = undefined;
        const request = try std.fmt.bufPrint(&buffer, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
        try self.conn.send(request);
    }

    fn onRecv(self: *Self, data: []const u8) !void {
        std.debug.print("onRecv: {} recv_buf.len: {}\n", .{ data.len, self.conn.recv_buf.buffer.len });
    }

    fn onClose(_: *Self, err: anyerror) void {
        if (err != error.TimerExpired)
            log.debug("connection close {}", .{err});
    }

    fn onConnectError(self: *Self, err: anyerror) void {
        self.allocator.destroy(self.connector);
        log.err("connect error {}", .{err});
    }
};
