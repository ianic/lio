const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;

/// Unlocker interface
pub const Unlocker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        unlock: *const fn (*anyopaque) void,
    };

    pub fn unlock(self: Unlocker) void {
        self.vtable.unlock(self.ptr);
    }
};

/// Copy On Write buffer
///
/// Append will copy into new instance if current one is read locked.
pub const Cow = struct {
    const Self = @This();

    allocator: mem.Allocator,
    rlock: usize = 0,
    zombie: bool = false,
    head: usize = 0,
    tail: usize = 0,
    data: []u8,

    pub fn init(allocator: mem.Allocator, size: usize) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .rlock = 0,
            .head = 0,
            .tail = 0,
            .data = try allocator.alloc(u8, roundUpToPageSize(size)),
            .zombie = false,
        };
        return self;
    }

    fn initAppend(allocator: mem.Allocator, bytes1: []const u8, bytes2: []const u8) !*Self {
        var self = try init(allocator, roundUpToPageSize(@min(bytes1.len * 2, bytes1.len + 2 * bytes2.len)));
        assert(self == try self.append(bytes1));
        assert(self == try self.append(bytes2));
        return self;
    }

    pub fn freeSize(self: Self) usize {
        return self.data.len - self.tail;
    }

    pub fn ensureCapacity(self: *Self, count: usize) !*Self {
        self.tryShrink();
        // There is enough free space
        if (self.freeSize() >= count) {
            return self;
        }
        // No locks safe to extend by reallocating
        if (self.rlock == 0) {
            const new_len = roundUpToPageSize(@min(self.data.len * 2, self.data.len + 2 * count));
            self.data = try self.allocator.realloc(self.data, new_len);
            return self;
        }
        // Create new, mark this one as zombie. Zombie should be destroyed when
        // last reader is gone (when last reader calls unlock).
        const data = self.data[self.head..self.tail];
        const new_len = roundUpToPageSize(@min(data.len * 2, data.len + 2 * count));
        var new = try init(self.allocator, new_len);
        if (data.len > 0) {
            @memcpy(new.getAssumeCapacity(count), data);
        }
        // assert(new == try new.append(data));
        self.zombie = true;
        return new;
    }

    pub fn getAssumeCapacity(self: *Self, count: usize) []u8 {
        assert(self.freeSize() >= count);
        defer self.tail += count;
        return self.data[self.tail..][0..count];
    }

    pub fn append(self: *Self, bytes: []const u8) !*Self {
        var self_or_new = try self.ensureCapacity(bytes.len);
        @memcpy(self_or_new.getAssumeCapacity(bytes.len), bytes);
        return self_or_new;

        // self.tryShrink();
        // // There is enough free space
        // if (self.freeSize() >= bytes.len) {
        //     @memcpy(self.data[self.tail..][0..bytes.len], bytes);
        //     self.tail += bytes.len;
        //     return self;
        // }
        // // No locks safe to extend by reallocating
        // if (self.rlock == 0) {
        //     const new_len = roundUpToPageSize(@min(self.data.len * 2, self.data.len + 2 * bytes.len));
        //     self.data = try self.allocator.realloc(self.data, new_len);
        //     assert(self == try self.append(bytes));
        //     return self;
        // }
        // // Create new, mark this one as zombie. Zombie should be destroyed when
        // // last reader is gone (when last reader calls unlock).
        // const new = try initAppend(self.allocator, self.data[self.head..self.tail], bytes);
        // self.zombie = true;
        // return new;
    }

    fn tryShrink(self: *Self) void {
        if (self.head == 0 or self.rlock != 0) return;
        if (self.head == self.tail) {
            self.head = 0;
            self.tail = 0;
            return;
        }
        mem.copyBackwards(u8, self.data, self.data[self.head..self.tail]);
        self.tail -= self.head;
        self.head = 0;
    }

    pub fn incHead(self: *Self, val: usize) void {
        self.head += val;
        assert(self.head <= self.tail);
        self.tryShrink();
    }

    fn lock(self: *Self) void {
        self.rlock += 1;
    }

    fn unlock(self: *Self) void {
        self.rlock -= 1;
        if (self.zombie and self.rlock == 0) {
            self.destroy();
            return;
        }
        self.tryShrink();
    }

    fn anyLock(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.lock();
    }

    fn anyUnlock(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.unlock();
    }

    pub fn deinit(self: *Self) void {
        self.zombie = true;
        if (self.rlock == 0) self.destroy();
    }

    pub fn destroy(self: *Self) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }

    /// Acguire part of the buffer, raises read lock which must be unlocked when
    /// returned buffer is no more needed. Lock prevents reallocation while
    /// buffer is in use.
    pub fn acquire(self: *Self, head: usize, tail: usize) struct { []const u8, Unlocker } {
        assert(self.tail >= head);
        assert(self.tail >= tail);
        self.lock();
        return .{
            self.data[head..tail], .{
                .ptr = self,
                .vtable = &.{
                    .unlock = anyUnlock,
                },
            },
        };
    }
};

const page_size = std.heap.pageSize();

fn roundUpToPageSize(value: usize) usize {
    if (value == 0) return page_size;
    return (value + (page_size - 1)) & ~(page_size - 1);
}

const testing = std.testing;

test roundUpToPageSize {
    if (page_size != 4096) return error.SkipZigTest;
    try testing.expectEqual(4096, page_size);
    try testing.expectEqual(4096, roundUpToPageSize(0));
    try testing.expectEqual(4096, roundUpToPageSize(1));
    try testing.expectEqual(4096, roundUpToPageSize(4096));
    try testing.expectEqual(4096 * 2, roundUpToPageSize(4097));
}

test Cow {
    var cb1 = try Cow.init(testing.allocator, 0);

    try testing.expectEqual(4096, cb1.data.len);
    try testing.expectEqual(cb1, try cb1.append("a" ** 4095));
    try testing.expectEqual(1, cb1.freeSize());
    // resize cb1
    try testing.expectEqual(cb1, try cb1.append("b" ** 2));
    try testing.expectEqual(4096 * 2, cb1.data.len);
    try testing.expectEqual(4095, cb1.freeSize());
    // read lock forces copy
    cb1.lock();
    var cb2 = try cb1.append("c" ** 4097);
    try testing.expect(cb1 != cb2);
    try testing.expectEqual(4096 * 2, cb1.data.len);
    try testing.expectEqual(4095, cb1.freeSize());
    try testing.expectEqual(4096 * 3, cb2.data.len);
    try testing.expectEqual(4094, cb2.freeSize());
    try testing.expectEqualSlices(u8, cb1.data[0..cb1.tail], cb2.data[0..cb1.tail]);
    try testing.expectEqualSlices(u8, "c" ** 4097, cb2.data[cb1.tail..cb2.tail]);

    cb1.unlock();
    cb2.deinit();
}

test "lockBuffer" {
    var cb1 = try Cow.init(testing.allocator, 0);
    try testing.expectEqual(4096, cb1.data.len);
    try testing.expectEqual(cb1, try cb1.append("a" ** 128));
    try testing.expectEqual(4096 - 128, cb1.freeSize());
    try testing.expectEqual(0, cb1.head);
    try testing.expectEqual(128, cb1.tail);

    const data, const rc = cb1.acquire(16, 32);
    try testing.expectEqual(16, data.len);
    cb1.deinit();
    try testing.expectEqualSlices(u8, "a" ** 16, data);
    try testing.expect(cb1.zombie);
    try testing.expectEqual(1, cb1.rlock);
    rc.unlock();
}
