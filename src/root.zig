const std = @import("std");
const linux = std.os.linux;

pub const Loop = @import("Loop.zig");
pub const BufferGroup = linux.IoUring.BufferGroup;

pub const tcp = struct {
    pub const Listener = @import("tcp.zig").Listener;
    pub const Connector = @import("tcp.zig").Connector;
};

pub const SyscallError = @import("errno.zig").Error;

pub const RecvErrorKind = enum {
    close,
    interrupt,
    cancel,
    unexpected,

    pub fn from(err: SyscallError) @This() {
        return switch (err) {
            error.ConnectionResetByPeer => .close,
            error.OperationCanceled => .cancel,
            error.InterruptedSystemCall => .interrupt,
            else => .unexpected,
            // TODO rethink
            // error.SocketOperationOnNonsocket
            // error.NoBufferSpaceAvailable
        };
    }
};

pub const SendErrorKind = enum {
    close,
    interrupt,
    cancel,
    unexpected,

    pub fn from(err: SyscallError) @This() {
        return switch (err) {
            error.BrokenPipe, error.ConnectionResetByPeer => .close,
            error.OperationCanceled => .cancel,
            error.InterruptedSystemCall => .interrupt,
            else => .unexpected,
            // TODO rethink
            // error.SocketOperationOnNonsocket
        };
    }
};

pub const ConnectErrorKind = enum {
    again,
    interrupt,
    cancel,
    unexpected,

    pub fn from(err: SyscallError) @This() {
        // ref: https://man7.org/linux/man-pages/man2/connect.2.html
        return switch (err) {
            error.ConnectionRefused, // ECONNREFUSED
            error.NetworkIsUnreachable, // ENETUNREACH
            error.NoRouteToHost, // EHOSTUNREACH
            error.ConnectionTimedOut, // ETIMEDOUT
            error.ConnectionResetByPeer, // ECONNRESET

            error.AddressAlreadyInUse, // EADDRINUSE
            error.OperationAlreadyInProgress, // EALREADY
            error.OperationNowInProgress, // EINPROGRESS
            error.TryAgain, // EAGAIN
            error.TransportEndpointIsAlreadyConnected, //  EISCONN
            => .again,

            error.OperationCanceled => .cancel,
            error.InterruptedSystemCall => .interrupt,
            else => .unexpected,
        };
    }
};
