const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;

pub const CommandType = enum(u8) {
    // sErver to client commands
    record = 0xE0,
    pos,
    tail,

    // Client to server commands
    append = 0xC0,
    subscribe,
    unsubscribe,
    seek,
    ack,
    credit,
    get_pos,
    get_tail,
};

/// Fields:
/// ref    - client's reference to the stream, set with subscribe
/// name   - stream name
///
/// credit - Number of records client is ready to accept for that stream. On
/// every sent record server decreases clients credit for that stream. When 0 is
/// reached no more messages is sent.
//
//
/// Record header
pub const Record = struct {
    sequence: u64,
    timestamp: u64,
};

/// Current position for this client in the stream, ack/seek moves current. Tail
/// is last record in the stream. Credit currnet server known clients credit.
pub const Pos = struct {
    ref: u32,
    name: []const u8,
    current: struct {
        sequence: u64,
        timestamp: u64,
    },
    tail: struct {
        sequence: u64,
        timestamp: u64,
    },
    credit: u32,
};

/// Response to the GetTail request. Returns position of the last record in the
/// stream.
pub const Tail = struct {
    ref: u32,
    name: []const u8,
    tail: struct {
        sequence: u64,
        timestamp: u64,
    },
};

pub const Append = struct {
    name: []const u8,
    sequence: u64,
    timestamp: u64,
};

/// Subscribe to the stream by name, sets client's stream reference for all
/// other communication. Clients chooses that reference.
pub const Subscribe = struct {
    ref: u32,
    name: []const u8,
    sequence: u64,
    timestamp: u64,
};

pub const Unsubscribe = struct {
    ref: u32,
};

/// Moves server side stream pointer
pub const Seek = struct {
    ref: u32,
    sequence: u64,
    timestamp: u64,
};

/// Acknowledges all records before and including one with sequence. Moves
/// server side current pointer.
pub const Ack = struct {
    ref: u32,
    sequence: u64,
};

/// Credit based flow control. Sets credit for the stream.
pub const Credit = struct {
    ref: u32,
    credit: u32,
};

pub const GetPos = struct {
    ref: u32,
};

pub const GetTail = struct {
    name: []const u8,
};

pub const Command = union(CommandType) {
    record: Record,
    pos: Pos,
    tail: Tail,

    append: Append,
    subscribe: Subscribe,
    unsubscribe: Unsubscribe,
    seek: Seek,
    ack: Ack,
    credit: Credit,
    get_pos: GetPos,
    get_tail: GetTail,

    pub fn encodedLength(cmd: Command) usize {
        return 1 + switch (cmd) {
            inline else => |t| BufferWriter.encodedLength(t),
        };
    }

    pub fn encode(cmd: Command, buffer: []u8) !void {
        if (buffer.len < encodedLength(cmd)) return error.NoSpaceLeft;
        switch (cmd) {
            inline else => |t| {
                var w = BufferWriter{ .buffer = buffer };
                w.byte(@intFromEnum(cmd));
                w.encode(t);
            },
        }
    }

    pub fn allocEncode(cmd: Command, allocator: mem.Allocator) ![]u8 {
        const buffer = try allocator.alloc(u8, cmd.encodedLength());
        cmd.encode(buffer) catch unreachable;
        return buffer;
    }
};

pub fn decode(buffer: []const u8) !Command {
    var r = BufferReader{ .buffer = buffer };
    const kind: CommandType = tryEnumFromInt(CommandType, try r.byte()) orelse return error.InvalidCommand;
    switch (kind) {
        inline else => |k| {
            var c = @unionInit(Command, @tagName(k), undefined);
            try r.decodeInto(&@field(c, @tagName(k)));
            return c;
        },
    }
}

fn tryEnumFromInt(comptime T: type, value: anytype) ?T {
    const info = @typeInfo(T).@"enum";
    inline for (info.fields) |field| {
        if (field.value == value) {
            return @field(T, field.name);
        }
    }
    return null;
}

test tryEnumFromInt {
    try testing.expectEqual(CommandType.pos, tryEnumFromInt(CommandType, 0xe1));
    try testing.expectEqual(CommandType.ack, tryEnumFromInt(CommandType, 0xc4));
    try testing.expectEqual(null, tryEnumFromInt(CommandType, 0xff));
}

const BufferWriter = struct {
    const Self = @This();

    buffer: []u8,
    pos: usize = 0,

    fn byte(self: *Self, b: u8) void {
        self.buffer[self.pos] = b;
        self.pos += 1;
    }

    fn int4(self: *Self, i: u32) void {
        mem.writeInt(u32, self.buffer[self.pos..][0..4], i, .big);
        self.pos += 4;
    }

    fn int8(self: *Self, i: u64) void {
        mem.writeInt(u64, self.buffer[self.pos..][0..8], i, .big);
        self.pos += 8;
    }

    fn string(self: *Self, s: []const u8) void {
        assert(s.len <= 0xff);
        self.byte(@intCast(s.len));
        @memcpy(self.buffer[self.pos..][0..s.len], s);
        self.pos += s.len;
    }

    fn encode(self: *Self, value: anytype) void {
        const info = @typeInfo(@TypeOf(value));
        inline for (info.@"struct".fields) |field| {
            switch (field.type) {
                inline []const u8, []u8 => self.string(@field(value, field.name)), // string
                u32 => self.int4(@field(value, field.name)),
                u64 => self.int8(@field(value, field.name)),
                else => self.encode(@field(value, field.name)), // inner struct
            }
        }
    }

    fn encodedLength(value: anytype) usize {
        var ret: usize = 0;
        const info = @typeInfo(@TypeOf(value));
        inline for (info.@"struct".fields) |field| {
            ret += switch (field.type) {
                inline []const u8, []u8 => @field(value, field.name).len + 1,
                u32 => 4,
                u64 => 8,
                else => BufferWriter.encodedLength(@field(value, field.name)), // inner struct
            };
        }
        return ret;
    }

    fn content(self: Self) []u8 {
        return self.buffer[0..self.pos];
    }
};

const BufferReader = struct {
    const Self = @This();

    buffer: []const u8,
    pos: usize = 0,

    const Error = error{NoSpaceLeft};

    fn byte(self: *Self) Error!u8 {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += 1;
        return self.buffer[self.pos];
    }

    fn int4(self: *Self) Error!u32 {
        if (self.pos + 4 > self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += 4;
        return mem.readInt(u32, self.buffer[self.pos..][0..4], .big);
    }

    fn int8(self: *Self) Error!u64 {
        if (self.pos + 8 > self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += 8;
        return mem.readInt(u64, self.buffer[self.pos..][0..8], .big);
    }

    fn string(self: *Self) Error![]const u8 {
        const len = try self.byte();
        if (self.pos + len > self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += len;
        return self.buffer[self.pos..][0..len];
    }

    fn decodeInto(self: *Self, ptr: anytype) Error!void {
        const info = @typeInfo(@typeInfo(@TypeOf(ptr)).pointer.child);
        inline for (info.@"struct".fields) |field| {
            switch (field.type) {
                inline []const u8, []u8 => @field(ptr, field.name) = try self.string(), // string
                u32 => @field(ptr, field.name) = try self.int4(),
                u64 => @field(ptr, field.name) = try self.int8(),
                else => try self.decodeInto(&@field(ptr, field.name)), // inner struct
            }
        }
    }

    fn decode(self: *Self, T: type) Error!T {
        var value: T = undefined;
        const info = @typeInfo(@TypeOf(value));
        inline for (info.@"struct".fields) |field| {
            if (self.pos == self.buffer.len) {
                if (field.defaultValue()) |default| {
                    @field(value, field.name) = default;
                } else {
                    return error.NoSpaceLeft;
                }
            } else {
                switch (field.type) {
                    inline []const u8, []u8 => @field(value, field.name) = try self.string(), // string
                    u32 => @field(value, field.name) = try self.int4(),
                    u64 => @field(value, field.name) = try self.int8(),
                    else => @field(value, field.name) = try self.decode(field.type), // inner struct
                }
            }
        }
        return value;
    }
};

test "encode/decode" {
    const cases: []const struct {
        value: Command,
        encoded_bytes: []const u8,
    } = &.{
        .{
            .value = .{ .record = .{
                .sequence = 0x1122334455667788,
                .timestamp = 0x99aabbccddeeff00,
            } },
            .encoded_bytes = &.{
                0xe0, // kind
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0, // timestamp
            },
        },
        .{
            .value = .{ .pos = .{
                .ref = 0xaabbccdd,
                .name = "stream name",
                .current = .{
                    .sequence = 0x1122334455667788,
                    .timestamp = 0x99aabbccddeeff00,
                },
                .tail = .{
                    .sequence = 0x1122334455667788 + 1,
                    .timestamp = 0x99aabbccddeeff00 + 1,
                },
                .credit = 0xddeeaadd,
            } },
            .encoded_bytes = &.{
                0xe1, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // ref
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // current.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0, // current.timestamp
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // tail.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // tail timestamp
                0xdd, 0xee, 0xaa, 0xdd, // credit
            },
        },
        .{
            .value = .{ .tail = .{
                .ref = 0xaabbccdd,
                .name = "stream name",
                .tail = .{
                    .sequence = 0x1122334455667788 + 1,
                    .timestamp = 0x99aabbccddeeff00 + 1,
                },
            } },
            .encoded_bytes = &.{
                0xe2, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // ref
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // tail.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // tail timestamp
            },
        },

        .{
            .value = .{ .append = .{
                .name = "append stream name",
                .sequence = 0x1122334455667788 + 1,
                .timestamp = 0x99aabbccddeeff00 + 1,
            } },
            .encoded_bytes = &.{
                0xc0, // kind
                0x12, 0x61, 0x70, 0x70, 0x65, 0x6E, 0x64, 0x20, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6D, 0x20, 0x6E, 0x61, 0x6D, 0x65, // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // timestamp
            },
        },
        .{
            .value = .{ .subscribe = .{
                .ref = 0xddeeaadd,
                .name = "subscribe stream name",
                .sequence = 0x1122334455667788 + 1,
                .timestamp = 0x99aabbccddeeff00 + 1,
            } },
            .encoded_bytes = &.{
                0xc1, // kind
                0xdd, 0xee, 0xaa, 0xdd, // ref
                0x15, 's', 'u', 'b', 's', 'c', 'r', 'i', 'b', 'e', ' ', 's', 't', 'r', 'e', 'a', 'm', ' ', 'n', 'a', 'm', 'e', // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // timestamp
            },
        },
        .{
            .value = .{ .unsubscribe = .{
                .ref = 0xddeeaaff,
            } },
            .encoded_bytes = &.{
                0xc2, // kind
                0xdd, 0xee, 0xaa, 0xff, // ref
            },
        },
        .{
            .value = .{ .seek = .{
                .ref = 0xaabbccdd,
                .sequence = 0x1122334455667788 + 1,
                .timestamp = 0x99aabbccddeeff00 + 1,
            } },
            .encoded_bytes = &.{
                0xc3, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // ref
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // timestamp
            },
        },
        .{
            .value = .{ .ack = .{
                .ref = 0xaabbccdd,
                .sequence = 0x1122334455667788 + 1,
            } },
            .encoded_bytes = &.{
                0xc4, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // ref
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
            },
        },
        .{
            .value = .{ .credit = .{
                .ref = 0xaabbccdd,
                .credit = 0x11223344,
            } },
            .encoded_bytes = &.{
                0xc5, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // ref
                0x11, 0x22, 0x33, 0x44, // credit
            },
        },
        .{
            .value = .{ .get_pos = .{
                .ref = 0xaabbccdd,
            } },
            .encoded_bytes = &.{
                0xc6, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // ref
            },
        },
        .{
            .value = .{ .get_tail = .{
                .name = "stream name",
            } },
            .encoded_bytes = &.{
                0xc7, // kind
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
            },
        },
    };

    for (cases) |case| {
        const cmd = case.value;

        const buffer = try testing.allocator.alloc(u8, cmd.encodedLength());
        defer testing.allocator.free(buffer);
        try cmd.encode(buffer);

        try testing.expectEqualSlices(u8, case.encoded_bytes, buffer);

        const cmd2 = try decode(buffer);
        try testing.expectEqualDeep(cmd, cmd2);
    }
}

test "decode with default value" {
    const T = struct {
        short: u32,
        string: []const u8,
        long1: u64 = 1,
        long2: u64 = 2,
    };
    const encoded: []const u8 = &.{
        0xaa, 0xbb, 0xcc, 0xdd, // ref
        0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // long
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0, // long
    };
    {
        var r = BufferReader{ .buffer = encoded };
        const t = try r.decode(T);
        try testing.expectEqual(0x1122334455667788, t.long1);
        try testing.expectEqual(0x99aabbccddeeff00, t.long2);
    }
    { // long2 to default value
        var r = BufferReader{ .buffer = encoded[0 .. encoded.len - 8] };
        const t = try r.decode(T);
        try testing.expectEqual(0x1122334455667788, t.long1);
        try testing.expectEqual(2, t.long2);
    }
    { // both to default value
        var r = BufferReader{ .buffer = encoded[0 .. encoded.len - 16] };
        const t = try r.decode(T);
        try testing.expectEqual(1, t.long1);
        try testing.expectEqual(2, t.long2);
    }
}
