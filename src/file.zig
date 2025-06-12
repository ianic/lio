const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const log = std.log.scoped(.tcp);
const testing = std.testing;

const Loop = @import("Loop.zig");
const SyscallError = @import("errno.zig").Error;

pub fn File(
    comptime Parent: type,
    comptime parent_field_name: []const u8,
    comptime onOpen: *const fn (*Parent) anyerror!void,
    comptime onRead: *const fn (*Parent, []u8) anyerror!void,
    comptime onWrite: *const fn (*Parent, []const u8) anyerror!void,
    comptime onError: *const fn (*Parent, anyerror) void,
) type {
    _ = onRead;
    return struct {
        const Self = @This();

        loop: *Loop,
        dir_fd: linux.fd_t,
        fd: linux.fd_t = -1,
        op: ?u32 = null,
        write_buffer: []const u8 = &.{},
        write_len: usize = 0,

        inline fn parent(self: *Self) *Parent {
            return @alignCast(@fieldParentPtr(parent_field_name, self));
        }

        pub fn init(loop: *Loop, dir_fd: linux.fd_t) Self {
            return .{
                .loop = loop,
                .dir_fd = dir_fd,
            };
        }

        pub fn open(self: *Self, path: [*:0]const u8) !void {
            try self.loop.openAt(
                Self,
                openComplete,
                "op",
                &self.op,
                self.dir_fd,
                path,
                .{ .ACCMODE = .RDWR, .CREAT = true },
                0o666,
            );
        }

        pub fn openRead(self: *Self, path: [*:0]const u8) !void {
            try self.loop.openAt(
                Self,
                openComplete,
                "op",
                &self.op,
                self.dir_fd,
                path,
                .{ .ACCMODE = .RDONLY, .CREAT = false },
                0o666,
            );
        }

        fn openComplete(self: *Self, res: SyscallError!linux.fd_t) void {
            if (res) |fd| {
                self.fd = fd;
                onOpen(self.parent()) catch |err| self.handleError(err);
            } else |err| {
                self.handleError(err);
            }
        }

        pub fn write(self: *Self, data: []const u8) !void {
            assert(self.write_buffer.len == 0);
            self.write_buffer = data;
            self.write_len = 0;
            self.writeSubmit();
        }

        fn writeSubmit(self: *Self) void {
            const buf = self.write_buffer[self.write_len..];
            self.loop.write(Self, writeComplete, "op", &self.op, self.fd, buf, Loop.offset_append) catch |err| {
                return self.handleError(err);
            };
        }

        fn writeComplete(self: *Self, res: SyscallError!u32) void {
            if (res) |n| {
                self.write_len += n;
                if (self.write_len < self.write_buffer.len) {
                    // short write
                    return self.writeSubmit();
                }
                const buf = self.write_buffer;
                self.write_buffer = &.{};
                onWrite(self.parent(), buf) catch |err| {
                    return self.handleError(err);
                };
            } else |err| switch (err) {
                error.InterruptedSystemCall => self.writeSubmit(),
                else => {
                    self.write_buffer = &.{};
                    self.handleError(err);
                },
            }
        }

        fn handleError(self: *Self, err: anyerror) void {
            self.close();
            onError(self.parent(), err);
        }

        fn close(self: *Self) void {
            if (self.fd < 0) return;
            if (self.op) |op| self.loop.detach(op);
            self.loop.close(self.fd) catch |err| {
                log.err("file close {}", .{err});
                return;
            };
            self.fd = -1;
        }
    };
}

test "open/write" {
    const T = struct {
        const Self = @This();
        call_count: usize = 0,
        err: ?anyerror = null,
        file: File(Self, "file", onOpen, onRead, onWrite, onError),

        fn init(loop: *Loop, dir: std.fs.Dir) Self {
            return .{
                .file = .init(loop, dir.fd),
            };
        }

        fn onOpen(self: *Self) !void {
            self.call_count += 1;
        }
        fn onError(self: *Self, err: anyerror) void {
            self.err = err;
            unreachable;
        }
        fn onRead(_: *Self, _: []u8) !void {}

        fn onWrite(self: *Self, _: []const u8) !void {
            //std.debug.print("onWrite: {s}", .{buf});
            self.call_count += 1;
        }
    };

    var tmp = std.testing.tmpDir(.{});
    //std.debug.print("{s}\n", .{tmp.sub_path});
    defer tmp.cleanup();

    var loop = try Loop.init(testing.allocator, .{
        .entries = 2,
        .fd_nr = 2,
    });
    defer loop.deinit();

    var t: T = .init(&loop, tmp.dir);
    try t.file.open("foo");

    try loop.tick();
    try testing.expect(t.file.fd >= 0);
    try testing.expectEqual(1, t.call_count);

    try t.file.write("iso medo u ducan\n");
    try loop.tick();
    try t.file.write("nije reko dobar dan\n");
    try loop.tick();

    const content = try (try tmp.dir.openFile("foo", .{})).readToEndAlloc(testing.allocator, 1024);
    defer testing.allocator.free(content);
    try testing.expectEqualStrings("iso medo u ducan\nnije reko dobar dan\n", content);
}

test "splice" {
    const pipe_fds = try std.posix.pipe();
    linux.pipe(&pipe_fds);
}
