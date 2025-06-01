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

    const host = "www.google.com";
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

    var cli: Client = .init(gpa, &loop, addr, config, host);
    cli.connect();

    while (true)
        try loop.tick();
}

fn getAddress(allocator: mem.Allocator, host: []const u8, port: u16) !net.Address {
    const list = try net.getAddressList(allocator, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.UnknownHostName;
    return list.addrs[0];
}

const Client = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    connector: io.tls.Connector(Self, "connector", onConnect),
    conn: io.tls.Connection(Self, "conn", onRecv, onClose),
    host: []const u8,

    pub fn init(
        allocator: mem.Allocator,
        loop: *io.Loop,
        addr: net.Address,
        config: tls.config.Client,
        host: []const u8,
    ) Self {
        return .{
            .allocator = allocator,
            .loop = loop,
            .connector = .init(loop, addr, config),
            .host = host,
            .conn = undefined,
        };
    }

    pub fn connect(self: *Self) void {
        self.connector.connect();
    }

    fn onConnect(
        self: *Self,
        fd: linux.fd_t,
        tls_conn: tls.nonblock.Connection,
        recv_buf: []const u8,
    ) !void {
        self.conn = .init(self.allocator, self.loop, fd, tls_conn);
        if (recv_buf.len > 0) {
            @memcpy(self.conn.recv_buf[0..recv_buf.len], recv_buf);
            self.conn.recv_tail = recv_buf.len;
        }
        try self.get(self.host);
    }

    fn get(self: *Self, host: []const u8) !void {
        var buffer: [256]u8 = undefined;
        const request = try std.fmt.bufPrint(&buffer, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
        try self.conn.send(request);
    }

    fn onRecv(_: *Self, data: []const u8) !void {
        std.debug.print("{s}", .{data});
    }

    fn onClose(_: *Self, _: anyerror) void {}
};
