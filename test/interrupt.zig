const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const io = @import("iox");

const log = std.log.scoped(.main);

// Connect with:
// $ nc -w0 localhost 9899
// Terminate with:
// $ pkill interrupt
// Signal:
// $ pkill -12 interrupt
pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    setSignalHandler();

    var loop = try io.Loop.init(.{
        .entries = 16,
        .fd_nr = 2,
        .op_list = io.Loop.OpList.init(gpa),
        .flags = linux.IORING_SETUP_SINGLE_ISSUER, //| linux.IORING_SETUP_SQPOLL,
    });
    defer loop.deinit();

    const Server = struct {
        const Self = @This();
        conn_count: usize = 0,
        loop: *io.Loop,

        fn onConnect(self: *Self, fd_err: anyerror!linux.fd_t) anyerror!void {
            log.debug("onConnect {any}", .{fd_err});
            self.conn_count += 1;
            const conn_fd = try fd_err;
            try self.loop.close(conn_fd);
        }
    };
    var server: Server = .{ .loop = &loop };

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9899);
    var listener: io.tcp.Listener = undefined;

    try loop.tcp.listen(&listener, addr, &server, Server.onConnect);

    //var thr = try std.Thread.spawn(.{}, connect, .{addr});
    while (server.conn_count < 1024) {
        log.debug("loop tick", .{});
        loop.tick() catch |err| {
            log.debug("tick err: {}", .{err});
            switch (err) {
                error.SignalInterrupt => {},
                else => return err,
            }
        };
        if (getSignal()) |sig|
            if (sig == posix.SIG.TERM) break;
    }
    //thr.join();

    try listener.close();
    log.debug("done", .{});
}

fn getSignal() ?c_int {
    const sig = signal.load(.monotonic);
    if (sig == posix.SIG.UNUSED)
        return null;
    signal.store(posix.SIG.UNUSED, .release);
    return sig;
}

fn connect(addr: std.net.Address) void {
    std.time.sleep(std.time.ns_per_ms * 500);
    _ = addr;
    posix.raise(posix.SIG.USR1) catch {};
}

var signal = std.atomic.Value(c_int).init(posix.SIG.UNUSED);

fn setSignalHandler() void {
    var act = posix.Sigaction{
        .handler = .{
            .handler = struct {
                fn wrapper(sig: c_int) callconv(.C) void {
                    signal.store(sig, .release);
                    log.debug("signal received {}", .{sig});
                }
            }.wrapper,
        },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.USR1, &act, null);
    posix.sigaction(posix.SIG.USR2, &act, null);
    posix.sigaction(posix.SIG.PIPE, &act, null);
}
