const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("iox");
const mem = std.mem;

const log = std.log.scoped(.main);
pub const std_options = std.Options{ .log_level = .debug };

var prng = std.Random.DefaultPrng.init(0);
const rnd = prng.random();
var buffer: []u8 = &.{};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var ops: [64]io.Loop.Op = undefined;
    var loop = try io.Loop.init(.{
        .entries = 256,
        .fd_nr = 32,
        .op_list = &ops,
    });
    defer loop.deinit();

    buffer = try gpa.alloc(u8, 64 * 1024);
    rnd.bytes(buffer);
    defer gpa.free(buffer);

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9900);

    var clients: [24]Client = undefined;
    for (&clients, 0..) |*cli, no| {
        try cli.init(&loop, addr, no);
    }

    while (true)
        try loop.tick();
}

const Client = struct {
    const Self = @This();

    loop: *io.Loop,
    addr: std.net.Address,
    no: usize,
    connect_timeout: linux.kernel_timespec = .{ .sec = 10, .nsec = 0 },

    fd: linux.fd_t = -1,
    buffer: [64 * 1024]u8 = undefined,
    send_head: u32 = 0,
    send_tail: u32 = 0,
    recv_pos: u32 = 0,

    fn init(self: *Self, loop: *io.Loop, addr: std.net.Address, no: usize) !void {
        self.* = .{
            .loop = loop,
            .addr = addr,
            .no = no,
        };
        try self.connect();
    }

    fn connect(self: *Self) !void {
        assert(self.fd < 0);
        _ = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, onSocket);
    }

    fn onSocket(self: *Self, res: anyerror!linux.fd_t) anyerror!void {
        if (res) |fd| {
            self.fd = fd;
            _ = try self.loop.connect(fd, &self.addr, &self.connect_timeout, self, onConnect);
        } else |err| {
            return err;
        }
    }

    fn onConnect(self: *Self, res: io.SyscallError!void) anyerror!void {
        if (res) {
            log.debug("{} connected", .{self.no});
            try self.echo();
        } else |err| switch (io.ConnectErrorKind.from(err)) {
            .again, .interrupt => try self.reconnect(),
            .cancel => unreachable,
            .unexpected => return err,
        }
    }

    // start echo cycle, send random bytes and expect to receive same bytes
    fn echo(self: *Self) !void {
        // if (self.send_tail > 0)
        //     log.debug("echo {}", .{self.send_tail});
        self.recv_pos = 0;
        self.send_tail = rnd.intRangeAtMost(u32, 16, 64 * 1024);
        self.send_head = 0;
        try self.send();
    }

    fn send(self: *Self) !void {
        _ = try self.loop.send(self.fd, buffer[self.send_head..self.send_tail], self, onSend);
    }

    fn onSend(self: *Self, res: io.SyscallError!u32) anyerror!void {
        if (res) |n| {
            self.send_head += n;
            if (self.send_head == self.send_tail) {
                try self.recv();
            } else {
                // can't happen because we are sending with msg.waitall in Loop.send
                log.err("{} short send", .{self.no});
                try self.send();
            }
        } else |err| switch (io.SendErrorKind.from(err)) {
            .close => try self.reconnect(),
            .interrupt => try self.send(),
            .cancel => unreachable,
            .unexpected => unreachable,
        }
    }

    fn recv(self: *Self) !void {
        _ = try self.loop.recv(self.fd, &self.buffer, self, onRecv);
    }

    fn onRecv(self: *Self, res: io.SyscallError!u32) anyerror!void {
        if (res) |n| {
            if (n == 0) return try self.reconnect();

            assert(std.mem.eql(u8, self.buffer[0..n], buffer[self.recv_pos..][0..n]));
            self.recv_pos += n;
            if (self.recv_pos == self.send_tail) {
                try self.echo();
            } else {
                try self.recv();
            }
        } else |err| switch (io.RecvErrorKind.from(err)) {
            .close => try self.reconnect(),
            .interrupt => try self.recv(),
            .cancel => unreachable,
            .unexpected => unreachable,
        }
    }

    fn reconnect(self: *Self) !void {
        // log.debug("{} close", .{self.no});
        try self.loop.close(self.fd);
        self.fd = -1;
        try self.loop.detach(self);
        try self.connect();
    }
};
