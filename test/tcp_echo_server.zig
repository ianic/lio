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
        .allocator = gpa,
        .loop = &loop,
        .addr = addr,
    };
    try listener.listenSubmit();

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
    addr: std.net.Address,
    fd: linux.fd_t = -1,

    fn listenSubmit(self: *Self) !void {
        assert(self.fd < 0);
        const wrap = struct {
            fn socketComplete(self_: *Self, res: io.SyscallError!linux.fd_t) anyerror!void {
                if (res) |fd| {
                    self_.fd = fd;
                    _ = try self_.loop.listen(fd, &self_.addr, .{ .reuse_address = true }, self_, @This().listenComplete);
                } else |err| switch (err) {
                    error.InterruptedSystemCall => try self_.listenSubmit(),
                    else => return err,
                }
            }

            fn listenComplete(self_: *Self, res: io.SyscallError!void) anyerror!void {
                if (res)
                    try self_.acceptSubmit()
                else |err| {
                    switch (err) {
                        error.InterruptedSystemCall => {},
                        error.AddressAlreadyInUse => {
                            log.err("listen {} {}", .{ self_.addr, err });
                        },
                        else => return err,
                    }
                    try self_.retry();
                }
            }
        };
        _ = try self.loop.socket(self.addr.any.family, linux.SOCK.STREAM, self, wrap.socketComplete);
    }

    fn acceptSubmit(self: *Self) !void {
        _ = try self.loop.accept(self.fd, self, struct {
            fn complete(self_: *Self, res: io.SyscallError!linux.fd_t) anyerror!void {
                if (res) |fd|
                    self_.acceptResolve(fd) catch |err| {
                        log.err("accept resolve {}", .{err});
                        self_.loop.close(fd) catch {};
                    }
                else |err| switch (err) {
                    error.InterruptedSystemCall => {},
                    error.SoftwareCausedConnectionAbort, // ECONNABORTED
                    error.NoBufferSpaceAvailable, // ENOBUFS
                    // No more fixed file descriptors, this connection if not
                    // accepted but we can continue working.
                    error.FileTableOverflow,
                    => {
                        log.warn("accept {} {}", .{ self_.addr, err });
                    },

                    else => return err,
                }
                try self_.acceptSubmit();
            }
        }.complete);
    }

    fn acceptResolve(self: *Self, fd: posix.fd_t) !void {
        const conn = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(conn);
        conn.* = .{
            .allocator = self.allocator,
            .loop = self.loop,
            .fd = fd,
        };
        try conn.recvSubmit();
    }

    fn retry(self: *Self) !void {
        try self.close();
        try self.listenSubmit();
    }

    pub fn close(self: *Self) !void {
        _ = try self.loop.close(self.fd);
        self.fd = -1;
        try self.loop.detach(self);
    }
};

const Connection = struct {
    const Self = @This();

    allocator: mem.Allocator,
    loop: *io.Loop,
    fd: linux.fd_t,
    buffer: [1024 * 64]u8 = undefined,
    head: u32 = 0,
    tail: u32 = 0,
    ops: [2]usize = undefined,

    fn recvSubmit(self: *Self) !void {
        self.head = 0;
        self.tail = 0;
        self.ops[0] = try self.loop.recv(self.fd, &self.buffer, self, struct {
            fn complete(self_: *Self, res: io.SyscallError!u32) anyerror!void {
                if (res) |n|
                    try self_.recvResolve(n)
                else |err| switch (err) {
                    error.ConnectionResetByPeer => try self_.close(),
                    error.InterruptedSystemCall => try self_.recvSubmit(),
                    error.OperationCanceled => unreachable,
                    else => return err,
                }
            }
        }.complete);
    }

    fn recvResolve(self: *Self, n: u32) !void {
        bytes += n;
        self.tail = n;
        try self.sendSubmit();
    }

    fn sendSubmit(self: *Self) !void {
        self.ops[1] = try self.loop.send(self.fd, self.buffer[self.head..self.tail], self, struct {
            fn complete(self_: *Self, res: io.SyscallError!u32) anyerror!void {
                if (res) |n|
                    try self_.sendResolve(n)
                else |err| switch (err) {
                    error.BrokenPipe,
                    error.ConnectionResetByPeer,
                    => try self_.close(),
                    error.InterruptedSystemCall => try self_.sendSubmit(),
                    error.OperationCanceled => unreachable,
                    else => return err,
                }
            }
        }.complete);
    }

    fn sendResolve(self: *Self, n: u32) !void {
        if (n == 0) return try self.close();
        self.head += n;
        if (self.head == self.tail) {
            try self.recvSubmit();
        } else {
            try self.sendSubmit();
        }
    }

    fn close(self: *Self) !void {
        try self.loop.close(self.fd);
        for (self.ops) |op| try self.loop.detachOp(op, self);
        self.allocator.destroy(self);
    }
};
