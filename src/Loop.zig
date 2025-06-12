const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const mem = std.mem;
const testing = std.testing;
const log = std.log.scoped(.loop);
const timespec = linux.kernel_timespec;
const SyscallError = @import("errno.zig").Error;

fn success(cqe: linux.io_uring_cqe) SyscallError!void {
    switch (cqe.err()) {
        .SUCCESS => return,
        else => |errno| return @import("errno.zig").toError(errno),
    }
}

pub const Options = struct {
    /// Number of submission queue entries
    entries: u16,
    /// io_uring init flags
    flags: u32 = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_SQPOLL,
    /// Number of kernel registered file descriptors
    fd_nr: u16,
};

pub const Op = struct {
    const Callback = *const fn (*Loop, Op, linux.io_uring_cqe) void;

    /// If null operations if free, not used.
    /// If not null holds pointer to operation index in op_list.
    ref: ?*?u32 = null,
    /// If null operation is detached, there is no handler waiting for completion.
    /// If not null holds completion callback.
    callback: ?Callback = null,

    args: union(enum) {
        recv: struct { buffer_group_id: u16 },
        timer: Timestamp,
    } = undefined,

    /// Break connection with completion handler.
    fn detach(self: *Op) void {
        // Clear parent reference to the operation
        if (self.ref) |ref| ref.* = null;
        self.callback = null;
    }

    const callbacks = struct {
        fn simple(
            comptime Parent: type,
            comptime onComplete: fn (*Parent, SyscallError!void) void,
            comptime parent_field_name: []const u8,
        ) Op.Callback {
            return struct {
                fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
                    onComplete(
                        @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                        if (success(cqe)) {} else |err| err,
                    );
                }
            }.callback;
        }
        fn fd(
            comptime Parent: type,
            comptime onComplete: fn (*Parent, SyscallError!linux.fd_t) void,
            comptime parent_field_name: []const u8,
        ) Op.Callback {
            return struct {
                fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
                    onComplete(
                        @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                        if (success(cqe)) @intCast(cqe.res) else |err| err,
                    );
                }
            }.callback;
        }
        fn len(
            comptime Parent: type,
            comptime onComplete: fn (*Parent, SyscallError!u32) void,
            comptime parent_field_name: []const u8,
        ) Op.Callback {
            return struct {
                fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
                    onComplete(
                        @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                        if (success(cqe)) @intCast(cqe.res) else |err| err,
                    );
                }
            }.callback;
        }
    };
};

const Loop = @This();
const yes_socket_option = std.mem.asBytes(&@as(u32, 1));
// Reserved values for user_data
const rsv_user_data = struct {
    const none: u64 = 0xff_ff_ff_ff_ff_ff_ff_ff;
    const skip_fail: u64 = 0xff_ff_ff_ff_ff_ff_ff_fe;
    const tick_timer: u64 = 0xff_ff_ff_ff_ff_ff_ff_fd;
    const timers: u64 = 0xff_ff_ff_ff_ff_ff_ff_fc;
};

allocator: mem.Allocator,
ring: linux.IoUring,
op_pool: ArrayPool(Op),
buffer_groups: std.ArrayListUnmanaged(linux.IoUring.BufferGroup) = .empty,
tick_timer_ts: ?timespec = null,
now: Timestamp = .{},
timers_pq: std.PriorityQueue(u32, *Loop, timersCompare),
timers_fire_ts: ?timespec = null,

metric: struct {
    /// Current number of in kernel operations
    active_op: usize = 0,
    /// Total number of processed operations
    processed_op: usize = 0,
    /// Total number of successful receives into provieded buffers
    recv: usize = 0,
    /// Total number of receive operations failed with no buffer available
    recv_no_buffer: usize = 0,
} = .{},

pub fn init(allocator: mem.Allocator, opt: Options) !Loop {
    var ring = try linux.IoUring.init(opt.entries, opt.flags);
    errdefer ring.deinit();
    try ring.register_files_sparse(opt.fd_nr);
    return .{
        .allocator = allocator,
        .ring = ring,
        .op_pool = try .init(allocator, @min(16, opt.fd_nr)),
        .timers_pq = .init(allocator, undefined), // TODO missing stable pointer to init
        .now = Timestamp.fromSystem(),
    };
}

pub fn deinit(self: *Loop) void {
    for (self.buffer_groups.items) |*bg| bg.deinit(self.allocator);
    self.buffer_groups.deinit(self.allocator);
    self.op_pool.deinit();
    self.timers_pq.deinit();
    self.ring.deinit();
}

/// Waits for nr retquest to be completed.
pub fn tickNr(self: *Loop, wait_nr: u32) !void {
    try self.submitTimers();
    _ = try self.ring.submit_and_wait(wait_nr);
    self.processCompletions();
}

/// Get completions and call operation callback for each completion.
fn processCompletions(self: *Loop) void {
    self.now = Timestamp.fromSystem();
    var ring = &self.ring;
    // Repeat in the case of overlapping ring
    while (true) {
        const ready = ring.cq_ready();
        if (ready == 0) break;
        // Peek list of ready cqes
        const head = ring.cq.head.* & ring.cq.mask;
        const tail = @min(ring.cq.cqes.len - head, ready);
        const cqes = ring.cq.cqes[head..][0..tail];
        // Call callback of each completion
        for (cqes) |cqe| {
            //log.debug("cqe: {}", .{cqe});
            if (cqe.user_data > std.math.maxInt(u32)) {
                // handle reseved user data values
                switch (cqe.user_data) {
                    rsv_user_data.none => {
                        success(cqe) catch |err| {
                            log.debug("cqe: res: {x}, user_data: {x}, err: {}", .{ cqe.res, cqe.user_data, err });
                        };
                    },
                    rsv_user_data.skip_fail => {},
                    rsv_user_data.tick_timer => self.tick_timer_ts = null,
                    rsv_user_data.timers => self.fireTimers(),
                    else => unreachable,
                }
                continue;
            }
            // Find operation by index from userdata, fire callback
            const idx: u32 = @intCast(cqe.user_data);
            const op: Op = self.op_pool.get(idx);
            if (!flagMore(cqe)) {
                self.releaseOp(idx);
            }
            if (op.callback) |callback| callback(self, op, cqe);
            self.metric.processed_op +%= 1;
        }
        ring.cq_advance(@intCast(cqes.len));
        if (cqes.len == ready) break;
    }
}

pub fn tick(self: *Loop) !void {
    return self.tickNr(1);
}

pub fn runFor(self: *Loop, ms: u32) !void {
    if (self.tick_timer_ts == null) {
        self.tick_timer_ts = Timestamp.zero.after(ms).toLinux();
        _ = try self.ring.timeout(rsv_user_data.tick_timer, &self.tick_timer_ts.?, 0, 0);
    }
    while (self.tick_timer_ts != null) {
        try self.tickNr(1);
    }
}

/// Tick loop while there is active operations
pub fn drain(self: *Loop) !void {
    while (self.metric.active_op > 0)
        try self.tick();
}

fn flagMore(cqe: linux.io_uring_cqe) bool {
    return cqe.flags & linux.IORING_CQE_F_MORE > 0;
}

pub const SubmitError = error{
    SystemResources,
    FileDescriptorInvalid,
    FileDescriptorInBadState,
    CompletionQueueOvercommitted,
    SubmissionQueueEntryInvalid,
    BufferInvalid,
    RingShuttingDown,
    OpcodeNotSupported,
    Unexpected,
};

pub const PrepareError = SubmitError || error{OutOfMemory};

/// Number of unused submission queue entries
/// Matched liburing io_uring_sq_space_left
fn sqSpaceLeft(self: *Loop) u32 {
    return @as(u32, @intCast(self.ring.sq.sqes.len)) - self.ring.sq_ready();
}

fn ensureSqCapacity(self: *Loop, count: u32) SubmitError!void {
    assert(count <= self.ring.sq.sqes.len);
    while (self.sqSpaceLeft() < count) {
        _ = self.ring.submit() catch |err| switch (err) {
            error.SignalInterrupt => continue,

            error.SystemResources => return error.SystemResources,
            error.FileDescriptorInvalid => return error.FileDescriptorInvalid,
            error.FileDescriptorInBadState => return error.FileDescriptorInBadState,
            error.CompletionQueueOvercommitted => return error.CompletionQueueOvercommitted,
            error.SubmissionQueueEntryInvalid => return error.SubmissionQueueEntryInvalid,
            error.BufferInvalid => return error.BufferInvalid,
            error.RingShuttingDown => return error.RingShuttingDown,
            error.OpcodeNotSupported => return error.OpcodeNotSupported,
            error.Unexpected => return error.Unexpected,
        };
    }
}

// Done with operation mark it as unused.
fn releaseOp(self: *Loop, idx: u32) void {
    const op: *Op = self.op_pool.getPtr(idx);
    if (op.callback != null) op.ref.?.* = null;
    self.op_pool.release(idx);
    self.metric.active_op -= 1;
}

fn acquireOp(self: *Loop, ref: *?u32, callback: Op.Callback) error{OutOfMemory}!struct { *Op, u32 } {
    assert(ref.* == null);
    const idx, const op = try self.op_pool.acquire();
    assert(op.ref == null);
    op.* = .{
        .ref = ref,
        .callback = callback,
    };
    ref.* = idx;
    self.metric.active_op += 1;
    return .{ op, idx };
}

/// Get io_uring direct socket. If there are no free socket we will get:
/// error.FileTableOverflow.
pub fn socket(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!linux.fd_t) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    domain: u32,
    socket_type: u32,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref orelse return)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);
    _ = self.ring.socket_direct_alloc(user_data, domain, socket_type, 0, 0) catch unreachable;
}

/// error.AddressAlreadyInUse
pub fn listen(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!void) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    /// Lifetime has to be until completion is received
    addr: *std.net.Address,
    opt: std.net.Address.ListenOptions,
) PrepareError!void {
    try self.ensureSqCapacity(if (opt.reuse_address) 4 else 2);
    _, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) {} else |err| err,
            );
        }
    }.callback);

    var sqe: *linux.io_uring_sqe = undefined;
    // Hardlink ensures that the last operation will get meaningful error. With
    // (soft)link in the case of error in bind onComplete will always get
    // error.OperationCanceled.
    if (opt.reuse_address) {
        sqe = self.ring.setsockopt(rsv_user_data.none, fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, yes_socket_option) catch unreachable;
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
        sqe = self.ring.setsockopt(rsv_user_data.none, fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, yes_socket_option) catch unreachable;
        sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    }
    sqe = self.ring.bind(rsv_user_data.none, fd, &addr.any, addr.getOsSockLen(), 0) catch unreachable;
    sqe.flags |= linux.IOSQE_IO_HARDLINK | linux.IOSQE_FIXED_FILE | linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = self.ring.listen(user_data, fd, opt.kernel_backlog, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// General syscall errors:
///   error.OperationCanceled
///   error.InterruptedSystemCall
/// Connect specific syscall errors to handle:
/// ref: https://man7.org/linux/man-pages/man2/connect.2.html
/// Network errors
///   error.ConnectionRefused, // ECONNREFUSED
///   error.NetworkIsUnreachable, // ENETUNREACH
///   error.NoRouteToHost, // EHOSTUNREACH
///   error.ConnectionTimedOut, // ETIMEDOUT
///   error.ConnectionResetByPeer, // ECONNRESET
/// Other documented to consider
///   error.AddressAlreadyInUse, // EADDRINUSE
///   error.OperationAlreadyInProgress, // EALREADY
///   error.OperationNowInProgress, // EINPROGRESS
///   error.TryAgain, // EAGAIN
///   error.TransportEndpointIsAlreadyConnected, //  EISCONN
pub fn connect(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!void) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    addr: *std.net.Address,
    connect_timeout: ?*timespec,
) PrepareError!void {
    try self.ensureSqCapacity(2);
    _, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) {} else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.connect(user_data, fd, &addr.any, addr.getOsSockLen()) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    if (connect_timeout) |t| {
        sqe.flags |= linux.IOSQE_IO_LINK;
        sqe = self.ring.link_timeout(rsv_user_data.none, t, 0) catch unreachable;
        sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    }
}

pub fn accept(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!linux.fd_t) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.accept_direct(user_data, fd, null, null, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Returns 0 on graceful shutdown.
///   error.ConnectionResetByPeer when remote host sends RST packet
/// Common syscall errors to handle:
///   error.OperationCanceled
///   error.InterruptedSystemCall
pub fn recv(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!u32) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer: []u8,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.recv(user_data, fd, .{ .buffer = buffer }, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn recvBufferGroup(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError![]u8) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer_group_id: u16,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    var op, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(loop: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            const ptr: *Parent = @alignCast(@fieldParentPtr(parent_field_name, op.ref.?));
            if (success(cqe)) {
                if (cqe.res == 0) return onComplete(ptr, &.{});
                var bg = loop.buffer_groups.items[op.args.recv.buffer_group_id];
                const buf = bg.get(cqe) catch unreachable;
                onComplete(ptr, buf);
                bg.put(cqe) catch unreachable;
                loop.metric.recv +%= 1;
            } else |err| {
                onComplete(ptr, err);
                switch (err) {
                    error.NoBufferSpaceAvailable => loop.metric.recv_no_buffer +%= 1,
                    else => {},
                }
            }
        }
    }.callback);
    op.args = .{ .recv = .{ .buffer_group_id = buffer_group_id } };

    var bg = self.buffer_groups.items[buffer_group_id];
    var sqe = bg.recv(user_data, fd, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Send on closed socket will return:
///   error.BrokenPipe - send on closed socket
///   error.ConnectionResetByPeer - send on forcefully closed socket (RST)
/// Common syscall errors to handle:
///   error.OperationCanceled
///   error.InterruptedSystemCall
pub fn send(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!u32) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer: []const u8,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            onComplete(
                @alignCast(@fieldParentPtr(parent_field_name, op.ref.?)),
                if (success(cqe)) @intCast(cqe.res) else |err| err,
            );
        }
    }.callback);

    var sqe = self.ring.send(user_data, fd, buffer, linux.MSG.WAITALL | linux.MSG.NOSIGNAL) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

/// Close file descriptor and cancel any pending operations on that fd.
pub fn close(self: *Loop, fd: linux.fd_t) SubmitError!void {
    if (fd < 0) return;
    try self.ensureSqCapacity(2);

    // Cancel any fd operations, it will probably fail because all fd operations
    // are already canceled.
    var sqe = self.ring.get_sqe() catch unreachable;
    sqe.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_FD_FIXED);
    sqe.flags |= linux.IOSQE_FIXED_FILE;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe.user_data = rsv_user_data.skip_fail; // ignore fail

    // Close socket
    sqe = self.ring.close_direct(rsv_user_data.none, @intCast(fd)) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

pub fn closePipe(self: *Loop, fds: [2]linux.fd_t) SubmitError!void {
    if (fds[0] < 0) return;
    try self.ensureSqCapacity(2);
    var sqe = self.ring.close(rsv_user_data.none, @intCast(fds[0])) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
    sqe = self.ring.close(rsv_user_data.none, @intCast(fds[1])) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Cancel single operation by index.
pub fn cancel(self: *Loop, user_data: u64) SubmitError!void {
    try self.ensureSqCapacity(1);
    var sqe = self.ring.cancel(rsv_user_data.none, user_data, 0) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

fn syncCancel(self: *Loop, user_data: u64) SyscallError!void {
    var reg = mem.zeroInit(linux.io_uring_sync_cancel_reg, .{
        .addr = user_data,
    });
    const res = linux.io_uring_register(
        self.ring.fd,
        .REGISTER_SYNC_CANCEL,
        @as(*const anyopaque, @ptrCast(&reg)),
        1,
    );
    switch (linux.E.init(res)) {
        .SUCCESS => return,
        else => |errno| return @import("errno.zig").toError(errno),
    }
}

pub fn cancelAll(self: *Loop) SubmitError!void {
    try self.ensureSqCapacity(1);
    var sqe = self.ring.cancel(rsv_user_data.none, 0, linux.IORING_ASYNC_CANCEL_ALL | linux.IORING_ASYNC_CANCEL_ANY) catch unreachable;
    sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
}

/// Detach (don't call callback when completed) single operation by index and
/// try to cancel that operation.
pub fn detach(self: *Loop, idx: u32) void {
    const op = self.op_pool.getPtr(idx);
    assert(op.ref != null);
    op.detach();
    switch (op.args) {
        .timer => self.timeoutRemove(idx),
        else => self.cancel(idx) catch {},
    }
}

pub fn addBufferGroup(
    self: *Loop,
    buffer_size: u32,
    buffers_count: u16,
) !u16 {
    const idx: u16 = @intCast(self.buffer_groups.items.len);
    try self.buffer_groups.ensureTotalCapacityPrecise(self.allocator, idx + 1);
    const bg = try linux.IoUring.BufferGroup.init(
        &self.ring,
        self.allocator,
        idx,
        buffer_size,
        buffers_count,
    );
    self.buffer_groups.appendAssumeCapacity(bg);
    return idx;
}

pub fn timeout(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    after_ms: u32,
) PrepareError!void {
    self.timers_pq.context = self;
    try self.timers_pq.ensureUnusedCapacity(1);
    // If already set find it and remove.
    if (parent_field_ptr.*) |idx| self.timeoutRemove(idx);

    var op, const idx = try self.acquireOp(parent_field_ptr, struct {
        fn callback(_: *Loop, op: Op, cqe: linux.io_uring_cqe) void {
            success(cqe) catch |err| {
                log.err("timer complete {}", .{err});
            };
            onComplete(@alignCast(@fieldParentPtr(parent_field_name, op.ref.?)));
        }
    }.callback);
    op.args = .{ .timer = self.now.after(after_ms) };
    self.timers_pq.add(@intCast(idx)) catch unreachable; // capacity ensured above
}

pub fn timeoutRemove(self: *Loop, idx: u32) void {
    for (self.timers_pq.items, 0..) |v, i| if (v == idx) {
        _ = self.timers_pq.removeIndex(i);
        self.releaseOp(idx);
        return;
    };
}

/// Finds earliest timer and prepares timeout operation for that timestamp.
fn submitTimers(self: *Loop) !void {
    const idx = self.timers_pq.peek() orelse return;
    const ts = self.op_pool.get(idx).args.timer;

    if (self.timers_fire_ts) |tc| {
        const fire_ts = Timestamp.fromLinux(tc);
        if (ts.compare(fire_ts) == .lt) {
            // Timer is set and new timestamp is less => cancel current timer.
            try self.cancel(rsv_user_data.timers);
            self.timers_fire_ts = .{ .sec = 0, .nsec = 0 };
        }
        return;
    }
    // No timer is set, set this one
    self.timers_fire_ts = ts.toLinux();
    errdefer self.timers_fire_ts = null;
    _ = try self.ring.timeout(
        rsv_user_data.timers,
        &self.timers_fire_ts.?,
        0,
        linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_REALTIME,
    );
}

/// Fires callbacks for all due timers.
fn fireTimers(self: *Loop) void {
    self.timers_fire_ts = null;
    while (self.timers_pq.peek()) |idx| {
        const op = self.op_pool.get(idx);
        if (op.args.timer.compare(self.now) == .gt) return;
        _ = self.timers_pq.remove();
        self.releaseOp(idx);
        if (op.callback) |callback| callback(self, op, undefined);
    }
}

fn timersCompare(loop: *Loop, a_idx: u32, b_idx: u32) std.math.Order {
    const ts_a = loop.op_pool.get(a_idx).args.timer;
    const ts_b = loop.op_pool.get(b_idx).args.timer;
    return ts_a.compare(ts_b);
}

pub fn openAt(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!linux.fd_t) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    dir_fd: linux.fd_t,
    path: [*:0]const u8,
    flags: linux.O,
    mode: linux.mode_t,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.acquireOp(parent_field_ptr, Op.callbacks.fd(Parent, onComplete, parent_field_name));
    _ = self.ring.openat_direct(user_data, dir_fd, path, flags, mode, linux.IORING_FILE_INDEX_ALLOC) catch unreachable;
}

pub const offset_append = std.math.maxInt(u64);

pub fn write(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!u32) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd: linux.fd_t,
    buffer: []const u8,
    offset: u64,
) PrepareError!void {
    try self.ensureSqCapacity(1);
    _, const user_data = try self.acquireOp(parent_field_ptr, Op.callbacks.len(Parent, onComplete, parent_field_name));
    var sqe = self.ring.write(user_data, fd, buffer, offset) catch unreachable;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

pub fn sendfile(
    self: *Loop,
    comptime Parent: type,
    comptime onComplete: fn (*Parent, SyscallError!u32) void,
    comptime parent_field_name: []const u8,
    parent_field_ptr: *?u32,
    fd_out: linux.fd_t,
    fd_in: linux.fd_t,
    pipe_fds: [2]linux.fd_t,
    offset: u64,
    len: u32,
) PrepareError!void {
    try self.ensureSqCapacity(2);
    _, const user_data = try self.acquireOp(parent_field_ptr, Op.callbacks.len(Parent, onComplete, parent_field_name));

    const SPLICE_F_NONBLOCK = 0x02;
    const no_offset = std.math.maxInt(u64);
    var sqe = self.ring.splice(rsv_user_data.none, fd_in, offset, pipe_fds[1], no_offset, len) catch unreachable;
    sqe.rw_flags = linux.IORING_SPLICE_F_FD_IN_FIXED + SPLICE_F_NONBLOCK;
    sqe.flags |= linux.IOSQE_IO_HARDLINK;
    sqe = self.ring.splice(user_data, pipe_fds[0], no_offset, fd_out, no_offset, len) catch unreachable;
    sqe.rw_flags = SPLICE_F_NONBLOCK;
    sqe.flags |= linux.IOSQE_FIXED_FILE;
}

test "socket" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 1,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,
        op: ?u32 = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            assert(self.op == null);
            self.call_count += 1;
            self.err = null;
            self.fd = err_fd catch |err| brk: {
                self.err = err;
                break :brk null;
            };
        }
    };
    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    { // success
        assert(ctx.op == null);
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        assert(ctx.op != null);
        try loop.tickNr(1);
        assert(ctx.op == null);
        try testing.expectEqual(1, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    { // success
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        try loop.tickNr(1);
        try testing.expectEqual(2, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
    const used_fd = ctx.fd.?;
    { // fail no more fds
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        try loop.tickNr(1);
        try testing.expectEqual(3, ctx.call_count);
        try testing.expect(ctx.err != null);
        try testing.expect(ctx.fd == null);
        try testing.expectEqual(ctx.err.?, error.FileTableOverflow);
    }
    { // return one used fd to the kernel
        _ = try loop.ring.close_direct(rsv_user_data.none, @intCast(used_fd));
        try loop.tickNr(1);
    }
    { // success
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        try loop.tickNr(1);
        try testing.expectEqual(4, ctx.call_count);
        try testing.expect(ctx.fd != null);
        try testing.expect(ctx.err == null);
    }
}

test "ensure ensureSqCapacity pushes sqes to the kernel" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 2,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,
        op: ?u32 = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            _ = self;
            _ = err_fd catch unreachable;
        }
    };
    var ctx1: Ctx = .{};
    var ctx2: Ctx = .{};
    var ctx3: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    // 2 entries but 3 prepared sqe
    // there was submit in ensureSqCapacity
    try loop.socket(Ctx, Ctx.onSocket, "op", &ctx1.op, domain, socket_type);
    try loop.socket(Ctx, Ctx.onSocket, "op", &ctx2.op, domain, socket_type);
    try loop.socket(Ctx, Ctx.onSocket, "op", &ctx3.op, domain, socket_type);
}

test "OutOfMemory on operations list unable to grow" {
    const ops_count = 8;
    var buf: [ops_count * @sizeOf(Op) + ops_count * @sizeOf(u32) + 6]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var loop = try Loop.init(fba.allocator(), .{
        .entries = 2,
        .fd_nr = ops_count,
    });
    defer loop.deinit();
    // fixed buffer allocator is full
    try testing.expectEqual(buf.len, fba.end_index);

    const Ctx = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        fd: ?linux.fd_t = null,
        op: ?u32 = null,

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            _ = self;
            _ = err_fd catch unreachable;
        }
    };

    var ctx: Ctx = .{};
    const domain = linux.AF.INET;
    const socket_type = linux.SOCK.STREAM;

    try testing.expectEqual(ops_count, loop.op_pool.list.capacity);
    for (0..ops_count) |_| {
        try loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type);
        ctx.op = null;
    }
    try testing.expectEqual(ops_count, loop.op_pool.list.items.len);
    loop.socket(Ctx, Ctx.onSocket, "op", &ctx.op, domain, socket_type) catch |err| switch (err) {
        error.OutOfMemory => return,
        else => unreachable,
    };
    unreachable;
}

test "listen (linked request) should return meaningful error" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 4,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Ctx = struct {
        const Self = @This();
        err: ?anyerror = null,
        op: ?u32 = null,

        fn onListen(self: *Self, _err: anyerror!void) void {
            _ = _err catch |e| {
                self.err = e;
            };
        }
    };

    var ctx: Ctx = .{};
    var addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 0);

    _ = try loop.listen(Ctx, Ctx.onListen, "op", &ctx.op, 0xffff, &addr, .{ .reuse_address = true });
    try loop.tickNr(4);
    try testing.expectEqual(error.BadFileNumber, ctx.err.?);
}

test "tcp server" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 16,
        .fd_nr = 2,
    });
    defer loop.deinit();

    const Server = struct {
        const Self = @This();
        addr: std.net.Address,
        loop: *Loop,
        buffer: [128]u8 = undefined,
        buffer_pos: usize = 0,
        listen_fd: ?linux.fd_t = null,
        conn_fd: ?linux.fd_t = null,
        conn_count: usize = 0,
        listen_op: ?u32 = null,
        recv_op: ?u32 = null,

        fn start(self: *Self) !void {
            try self.loop.socket(Self, onSocket, "listen_op", &self.listen_op, self.addr.any.family, linux.SOCK.STREAM);
        }

        fn onSocket(self: *Self, err_fd: anyerror!linux.fd_t) void {
            const fd = err_fd catch unreachable;
            self.listen_fd = fd;
            self.loop.listen(
                Self,
                onListen,
                "listen_op",
                &self.listen_op,
                fd,
                &self.addr,
                .{ .reuse_address = true },
            ) catch unreachable;
        }

        fn onListen(self: *Self, maybe_err: anyerror!void) void {
            _ = maybe_err catch unreachable;
            self.loop.accept(Self, onAccept, "listen_op", &self.listen_op, self.listen_fd.?) catch unreachable;
        }

        fn onAccept(self: *Self, err_fd: anyerror!linux.fd_t) void {
            const fd = err_fd catch unreachable;
            self.conn_fd = fd;
            self.loop.recv(Self, onRecv, "recv_op", &self.recv_op, fd, self.buffer[self.buffer_pos..]) catch unreachable;
        }

        fn onRecv(self: *Self, err_n: anyerror!u32) void {
            const n = err_n catch unreachable;
            self.conn_count += 1;
            self.buffer_pos += n;
            self.loop.close(self.conn_fd.?) catch unreachable;
            self.conn_fd = null;
            self.loop.accept(Self, onAccept, "listen_op", &self.listen_op, self.listen_fd.?) catch unreachable;
        }
    };

    const addr: std.net.Address = try std.net.Address.resolveIp("127.0.0.1", 9990);
    var server: Server = .{
        .loop = &loop,
        .addr = addr,
    };

    try server.start();
    var thr = try std.Thread.spawn(.{}, testSend, .{addr});
    while (server.conn_count < 4) {
        try loop.tickNr(1);
    }
    thr.join();

    try testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3 }, server.buffer[0..server.buffer_pos]);
}

fn testSend(addr: std.net.Address) void {
    var n: usize = 0;
    while (n < 4) {
        var stream = std.net.tcpConnectToAddress(addr) catch |err| switch (err) {
            error.ConnectionRefused => continue,
            else => unreachable,
        };
        stream.writeAll(&[_]u8{@intCast(n)}) catch unreachable;
        stream.close();
        n += 1;
    }
}

test "size" {
    try testing.expectEqual(32, @sizeOf(Op));
}

test "timers" {
    const T = struct {
        const Self = @This();
        op1: ?u32 = null,
        op2: ?u32 = null,

        call_count: usize = 0,
        fn onTimer(self: *Self) void {
            self.call_count += 1;
        }
    };

    var loop = try Loop.init(testing.allocator, .{
        .entries = 4,
        .fd_nr = 2,
    });
    defer loop.deinit();

    var t: T = .{};
    {
        try loop.timeout(T, T.onTimer, "op1", &t.op1, 30);
        try loop.timeout(T, T.onTimer, "op2", &t.op2, 20);

        try testing.expectEqual(2, loop.timers_pq.count());
        try testing.expectEqual(0, t.op1.?);
        try testing.expectEqual(1, t.op2.?);

        try loop.tickNr(1);
        try testing.expectEqual(1, t.call_count);
        try testing.expectEqual(1, loop.timers_pq.count());
        try loop.tickNr(1);
        try testing.expectEqual(2, t.call_count);
        try testing.expectEqual(0, loop.timers_pq.count());
    }
    { // cancel previous longer timer
        t.call_count = 0;
        try loop.timeout(T, T.onTimer, "op1", &t.op1, 30);
        try testing.expect(t.op1 != null);
        try loop.submitTimers();
        // set shorter timer while longer is submitted
        try loop.timeout(T, T.onTimer, "op2", &t.op2, 20);
        try testing.expect(t.op2 != null);

        try loop.tickNr(1); // cancel operation
        try testing.expectEqual(0, t.call_count);
        try loop.tickNr(1); // op2 is fired
        try testing.expect(t.op2 == null);
        try testing.expect(t.op1 != null);
        try testing.expectEqual(1, t.call_count);
        try loop.tickNr(1);
        try testing.expect(t.op1 == null);
    }
    { // reset same timer to the new value
        t.call_count = 0;
        try loop.timeout(T, T.onTimer, "op1", &t.op1, 20);
        try testing.expectEqual(1, loop.timers_pq.count());
        const ts1 = loop.op_pool.get(loop.timers_pq.peek().?).args.timer;
        try testing.expectEqual(1, loop.metric.active_op);
        try loop.timeout(T, T.onTimer, "op1", &t.op1, 30);
        try testing.expectEqual(1, loop.timers_pq.count());
        const ts2 = loop.op_pool.get(loop.timers_pq.peek().?).args.timer;
        try testing.expect(ts1.compare(ts2) == .lt);
        try testing.expectEqual(1, loop.metric.active_op);
    }

    { // detached
        try testing.expect(t.op1 != null);
        try testing.expectEqual(1, loop.timers_pq.count());
        loop.detach(t.op1.?);
        try testing.expect(t.op1 == null);
        try testing.expectEqual(0, loop.timers_pq.count());
    }
}

fn ArrayPool(T: type) type {
    return struct {
        const Self = @This();

        list: std.ArrayList(T),
        free: std.ArrayList(u32),

        pub fn init(allocator: mem.Allocator, num: usize) !Self {
            return .{
                .list = try std.ArrayList(T).initCapacity(allocator, num),
                .free = try std.ArrayList(u32).initCapacity(allocator, num),
            };
        }

        pub fn deinit(self: *Self) void {
            self.free.deinit();
            self.list.deinit();
        }

        pub fn acquire(self: *Self) !struct { u32, *T } {
            if (self.free.pop()) |idx| {
                return .{ @intCast(idx), &self.list.items[idx] };
            }
            try self.list.append(.{});
            try self.free.ensureTotalCapacityPrecise(self.list.capacity);
            const idx = self.list.items.len - 1;
            return .{ @intCast(idx), &self.list.items[idx] };
        }

        pub fn release(self: *Self, idx: u32) void {
            self.free.appendAssumeCapacity(idx);
            self.list.items[idx] = .{};
        }

        pub fn get(self: *Self, idx: u32) T {
            return self.list.items[idx];
        }

        pub fn getPtr(self: *Self, idx: u32) *T {
            return &self.list.items[idx];
        }
    };
}

test "ArrayPool" {
    const T = struct {
        val: usize = 0,
    };

    var pool = try ArrayPool(T).init(testing.allocator, 2);
    defer pool.deinit();
    try testing.expectEqual(0, pool.list.items.len);
    try testing.expectEqual(2, pool.free.capacity);
    try testing.expectEqual(2, pool.list.capacity);
    try testing.expectEqual(0, (try pool.acquire())[0]);
    try testing.expectEqual(2, pool.list.capacity);
    try testing.expectEqual(1, (try pool.acquire())[0]);
    try testing.expectEqual(2, pool.list.capacity);
    try testing.expectEqual(2, (try pool.acquire())[0]);
    try testing.expect(pool.list.capacity > 2);
    try testing.expectEqual(pool.list.capacity, pool.free.capacity);
    try testing.expectEqual(0, pool.free.items.len);
    pool.release(2);
    pool.release(1);
    try testing.expectEqual(2, pool.free.items.len);
    try testing.expectEqual(2, pool.free.items.len);
    try testing.expectEqual(1, (try pool.acquire())[0]);
    try testing.expectEqual(1, pool.free.items.len);
}

const Timestamp = struct {
    const Self = @This();
    const zero: Self = .{};

    value: u64 = 0,

    fn toLinux(self: Self) linux.kernel_timespec {
        const sec: i64 = @intCast(self.value / std.time.ns_per_s);
        const nsec: i64 = @intCast(self.value % std.time.ns_per_s);
        return .{ .sec = sec, .nsec = nsec };
    }

    fn fromLinux(tc: linux.kernel_timespec) Timestamp {
        return .{ .value = @as(u64, @intCast(tc.sec)) * std.time.ns_per_s + @as(u64, @intCast(tc.nsec)) };
    }

    fn fromSystem() Self {
        const ts = std.posix.clock_gettime(.REALTIME) catch |err| switch (err) {
            error.UnsupportedClock => unreachable,
            error.Unexpected => {
                log.err("clock_gettime: {}", .{err});
                return .{};
            },
        };
        return .{ .value = @intCast(ts.sec * std.time.ns_per_s + ts.nsec) };
    }

    fn after(self: Self, ms: u32) Self {
        return .{ .value = self.value + @as(u64, ms) * std.time.ns_per_ms };
    }

    fn compare(self: Self, other: Self) std.math.Order {
        return std.math.order(self.value, other.value);
    }
};

test "timestam from/to Linux" {
    const ts = Timestamp.fromSystem();
    try testing.expectEqual(ts, Timestamp.fromLinux(ts.toLinux()));
    // std.debug.print("ts: \n{}\n{}\n{}\n{}\n", .{
    //     ts,
    //     Timestamp.fromLinux(ts.toLinux()),
    //     ts.toLinux(),
    //     try std.posix.clock_gettime(.REALTIME),
    // });
}

test "syncCancel" {
    var loop = try Loop.init(testing.allocator, .{
        .entries = 4,
        .fd_nr = 2,
        .flags = 0,
    });
    defer loop.deinit();

    const tc: timespec = .{ .sec = 1, .nsec = 0 };
    _ = try loop.ring.timeout(0xab, &tc, 0, 0);
    try testing.expectEqual(1, try loop.ring.submit());

    try loop.syncCancel(0xab);
    const cqes = loop.peekCq();
    try testing.expectEqual(1, cqes.len);
    const cqe = cqes[0];
    try testing.expectEqual(0xab, cqe.user_data);
    try testing.expectEqual(.CANCELED, cqe.err());
    loop.ring.cq_advance(@intCast(cqes.len));
}

fn peekCq(self: *Loop) []linux.io_uring_cqe {
    const ring = &self.ring;
    const ready = ring.cq_ready();
    const head = ring.cq.head.* & ring.cq.mask;
    const tail = @min(ring.cq.cqes.len - head, ready);
    return ring.cq.cqes[head..][0..tail];
}
