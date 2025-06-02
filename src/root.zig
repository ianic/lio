const std = @import("std");
const mem = std.mem;
const linux = std.os.linux;

pub const Loop = @import("Loop.zig");
pub const BufferGroup = linux.IoUring.BufferGroup;

pub const SyscallError = @import("errno.zig").Error;

pub const tcp = @import("tcp.zig");
pub const tls = @import("tls.zig");

test {
    _ = @import("tls.zig");
}

pub const UnusedDataBuffer = struct {
    const Self = @This();
    buffer: []u8 = &.{},

    pub fn append(self: *Self, allocator: mem.Allocator, data: []u8) ![]u8 {
        if (self.buffer.len == 0) {
            // nothing to append to
            return data;
        }
        const old_len = self.buffer.len;
        self.buffer = try allocator.realloc(self.buffer, old_len + data.len);
        @memcpy(self.buffer[old_len..], data);
        return self.buffer;
    }

    pub fn set(self: *Self, allocator: mem.Allocator, unused: []const u8) !void {
        if (unused.ptr == self.buffer.ptr and unused.len == self.buffer.len) {
            // nothing changed
            return;
        }
        const old_buffer = self.buffer;
        if (unused.len > 0) {
            self.buffer = try allocator.dupe(u8, unused);
        } else {
            self.buffer = &.{};
        }
        if (old_buffer.len > 0) {
            allocator.free(old_buffer);
        }
    }

    pub fn deinit(self: *Self, allocator: mem.Allocator) void {
        allocator.free(self.buffer);
    }
};
