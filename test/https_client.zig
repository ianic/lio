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
    //const host = "oup.com";
    const addr = try getAddress(gpa, host, 443);

    // tls config
    var root_ca = try tls.config.cert.fromSystem(gpa);
    defer root_ca.deinit(gpa);
    var diagnostic: tls.config.Client.Diagnostic = .{};
    const config: tls.config.Client = .{
        .host = host,
        .root_ca = root_ca,
        .diagnostic = &diagnostic, // TODO: remove
    };

    var loop = try io.Loop.init(gpa, .{
        .entries = 256,
        .fd_nr = 32,
    });
    defer loop.deinit();

    var cli: Connector = .init(gpa, &loop, addr, config, host);
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

const Connector = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    tls: io.tls.Connector(Self, "tls", onConnect),
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
            .tls = .init(loop, addr, config),
            .host = host,
        };
    }

    pub fn connect(self: *Self) void {
        self.tls.connect();
    }

    fn onConnect(
        self: *Connector,
        fd: linux.fd_t,
        tls_conn: tls.nonblock.Connection,
        recv_buf: []const u8,
    ) !void {
        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);

        conn.* = .init(self.allocator, self.loop, fd, tls_conn);
        if (recv_buf.len > 0) {
            @memcpy(conn.recv_buf[0..recv_buf.len], recv_buf);
            conn.recv_tail = recv_buf.len;
        }
        try conn.get(self.host);
    }
};

const Connection = struct {
    const Self = @This();

    allocator: mem.Allocator,
    tcp: io.tcp.Connection(Self, "tcp", onRecv, onSend, onClose),
    tls: tls.nonblock.Connection,

    recv_buf: [tls.max_ciphertext_record_len]u8 = undefined,
    recv_tail: usize = 0,

    fn init(allocator: mem.Allocator, loop: *io.Loop, fd: linux.fd_t, tls_conn: tls.nonblock.Connection) Self {
        return .{
            .allocator = allocator,
            .tcp = .init(loop, fd),
            .tls = tls_conn,
            .recv_tail = 0,
        };
    }

    fn get(self: *Self, host: []const u8) !void {
        if (self.recv_tail > 0)
            try self.decrypt();

        var buffer: [256]u8 = undefined;
        const request = try std.fmt.bufPrint(&buffer, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});

        const ciphertext = try self.allocator.alloc(u8, self.tls.encryptedLength(request.len));
        const res = try self.tls.encrypt(request, ciphertext);
        self.tcp.send(res.ciphertext);
        self.tcp.recv(self.recv_buf[self.recv_tail..]);
    }

    fn onSend(self: *Self, buf: []const u8) !void {
        self.allocator.free(buf);
    }

    fn onRecv(self: *Self, n: u32) !void {
        self.recv_tail += n;
        try self.decrypt();
        self.tcp.recv(self.recv_buf[self.recv_tail..]);
    }

    fn decrypt(self: *Self) !void {
        const res = try self.tls.decrypt(self.recv_buf[0..self.recv_tail], &self.recv_buf);
        if (res.cleartext.len > 0)
            std.debug.print("{s}", .{res.cleartext});

        if (res.unused_ciphertext.len == 0) {
            self.recv_tail = 0;
        } else if (res.unused_ciphertext.len > 0) {
            @memmove(self.recv_buf[0..res.unused_ciphertext.len], res.unused_ciphertext);
            self.recv_tail = res.unused_ciphertext.len;
        }
    }

    fn onClose(self: *Self, err: anyerror) void {
        switch (err) {
            error.EndOfFile => {
                return;
            },
            error.BrokenPipe, error.ConnectionResetByPeer => {
                log.debug("connection close {}", .{err});
            },
            else => {
                log.err("connection close {}", .{err});
            },
        }
        _ = self;
        unreachable;
        //self.parent.onError(err);
    }
};
