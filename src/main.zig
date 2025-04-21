const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const linux = std.os.linux;
const IoUring = linux.IoUring;
const socket_t = std.posix.socket_t;

const log = std.log.scoped(.main);

pub fn main() !void {
    var loop = try Loop.init(16);
    defer loop.deinit();

    try loop.ring.register_files_sparse(4);
    // ako ih nema dovoljno dobijem: FileTableOverflow, // NFILE = 23 File table overflow

    var addr: net.Address = try std.net.Address.resolveIp("127.0.0.1", 9898);
    var listen_fd: posix.fd_t = 0;
    const yes_socket_option: u32 = 1;
    const yes = mem.asBytes(&yes_socket_option);
    var cqes: [4]linux.io_uring_cqe = undefined;
    assert(loop.ring.sq_ready() == 0);

    _ = try loop.ring.socket_direct_alloc(1, addr.any.family, posix.SOCK.STREAM, 0, 0);

    _ = try loop.ring.submit();
    var n = try loop.ring.copy_cqes(&cqes, 1);
    log.debug("cqes: {}", .{n});
    for (cqes[0..n]) |cqe| {
        log.debug("{}", .{cqe});
        assert(cqe.res >= 0);
        listen_fd = @intCast(cqe.res);
    }

    // ensure sqe ready capacity
    assert(loop.ring.sq.sqes.len - loop.ring.sq_ready() >= 5);
    // var sqe = try loop.ring.socket_direct(1, addr.any.family, posix.SOCK.STREAM, 0, 0, listen_fd);
    // sqe.flags |= linux.IOSQE_IO_LINK;
    var sqe = try loop.ring.setsockopt(2, listen_fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes);
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
    sqe = try loop.ring.setsockopt(3, listen_fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes);
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
    sqe = try loop.ring.bind(4, listen_fd, &addr.any, addr.getOsSockLen(), 0);
    sqe.flags |= linux.IOSQE_IO_LINK | linux.IOSQE_FIXED_FILE;
    sqe = try loop.ring.listen(5, listen_fd, 128, 0);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    //assert(loop.ring.sq_ready() == 6);

    _ = try loop.ring.submit();
    n = try loop.ring.copy_cqes(&cqes, 4);
    log.debug("cqes: {}", .{n});
    for (cqes[0..n]) |cqe| {
        log.debug("{}", .{cqe});
        assert(cqe.res >= 0);
    }

    while (true) {
        var buffer: [4096]u8 = undefined;
        var conn_fd: posix.fd_t = 0;
        var accept_addr: posix.sockaddr align(4) = undefined;
        var accept_addr_size: posix.socklen_t = @sizeOf(posix.sockaddr);

        sqe = try loop.ring.accept_direct(6, listen_fd, &accept_addr, &accept_addr_size, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;

        _ = try loop.ring.submit();
        n = try loop.ring.copy_cqes(&cqes, 1);
        log.debug("cqes: {}", .{n});
        for (cqes[0..n]) |cqe| {
            log.debug("{}", .{cqe});
            assert(cqe.res > 0);
            conn_fd = @intCast(cqe.res);
        }

        sqe = try loop.ring.recv(7, conn_fd, .{ .buffer = &buffer }, 0);
        sqe.flags |= linux.IOSQE_FIXED_FILE;

        _ = try loop.ring.submit();
        n = try loop.ring.copy_cqes(&cqes, 1);
        log.debug("cqes: {}", .{n});
        for (cqes[0..n]) |cqe| {
            log.debug("{}, non empty: {}", .{ cqe, cqe.flags & linux.IORING_CQE_F_SOCK_NONEMPTY });
            assert(cqe.res > 0);
        }

        _ = try loop.ring.close_direct(8, @intCast(conn_fd));

        _ = try loop.ring.submit();
        n = try loop.ring.copy_cqes(&cqes, 1);
        log.debug("cqes: {}", .{n});
        for (cqes[0..n]) |cqe| {
            log.debug("{}", .{cqe});
            assert(cqe.res == 0);
        }
    }
}

pub const Loop = struct {
    const Self = @This();

    ring: IoUring,

    pub fn init(entries: u16) !Self {
        return initWithFlags(entries, linux.IORING_SETUP_SQPOLL | linux.IORING_SETUP_SINGLE_ISSUER);
    }

    pub fn initWithFlags(entries: u16, flags: u32) !Self {
        return .{ .ring = try IoUring.init(entries, flags) };
    }

    pub fn deinit(self: *Self) void {
        self.ring.deinit();
    }
};
