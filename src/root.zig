const std = @import("std");
const linux = std.os.linux;

pub const Loop = @import("Loop.zig");
pub const BufferGroup = linux.IoUring.BufferGroup;

pub const tcp = struct {
    pub const Listener = @import("tcp.zig").Listener;
    pub const Connector = @import("tcp.zig").Connector;
};

pub const SyscallError = @import("errno.zig").Error;
