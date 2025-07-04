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
    seek,
    ack,
    credit,
    get_pos,
    get_tail,
};

pub const Record = struct {
    sequence: u64,
    timestamp: u64,
};

pub const Pos = struct {
    id: u32,
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

pub const Tail = struct {
    id: u32,
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

pub const Seek = struct {
    id: u32,
    sequence: u64,
    timestamp: u64,
};

pub const Ack = struct {
    id: u32,
    sequence: u64,
};

pub const Credit = struct {
    id: u32,
    credit: u32,
};

pub const GetPos = struct {
    id: u32,
};

pub const GetTail = struct {
    name: []const u8,
};

pub const Command = union(CommandType) {
    record: Record,
    pos: Pos,
    tail: Tail,

    append: Append,
    seek: Seek,
    ack: Ack,
    credit: Credit,
    get_pos: GetPos,
    get_tail: GetTail,

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

    pub fn encodedLength(c: Command) usize {
        return 1 + switch (c) {
            inline else => |t| BufferWriter.encodedLength(t),
        };
    }

    pub fn encode(c: Command, buffer: []u8) !void {
        if (buffer.len < encodedLength(c)) return error.NoSpaceLeft;
        switch (c) {
            inline else => |t| {
                var w = BufferWriter{ .buffer = buffer };
                w.byte(@intFromEnum(c));
                w.encode(t);
            },
        }
    }
};

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
    try testing.expectEqual(CommandType.ack, tryEnumFromInt(CommandType, 0xc2));
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
                else => encodedLength(@field(value, field.name)), // inner struct
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
            switch (field.type) {
                inline []const u8, []u8 => @field(value, field.name) = try self.string(), // string
                u32 => @field(value, field.name) = try self.int4(),
                u64 => @field(value, field.name) = try self.int8(),
                else => @field(value, field.name) = try self.decode(field.type), // inner struct
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
                .id = 0xaabbccdd,
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
                0xaa, 0xbb, 0xcc, 0xdd, // id
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
                .id = 0xaabbccdd,
                .name = "stream name",
                .tail = .{
                    .sequence = 0x1122334455667788 + 1,
                    .timestamp = 0x99aabbccddeeff00 + 1,
                },
            } },
            .encoded_bytes = &.{
                0xe2, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
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
            .value = .{ .seek = .{
                .id = 0xaabbccdd,
                .sequence = 0x1122334455667788 + 1,
                .timestamp = 0x99aabbccddeeff00 + 1,
            } },
            .encoded_bytes = &.{
                0xc1, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // timestamp
            },
        },
        .{
            .value = .{ .ack = .{
                .id = 0xaabbccdd,
                .sequence = 0x1122334455667788 + 1,
            } },
            .encoded_bytes = &.{
                0xc2, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
            },
        },
        .{
            .value = .{ .credit = .{
                .id = 0xaabbccdd,
                .credit = 0x11223344,
            } },
            .encoded_bytes = &.{
                0xc3, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0x11, 0x22, 0x33, 0x44, // credit
            },
        },
        .{
            .value = .{ .get_pos = .{
                .id = 0xaabbccdd,
            } },
            .encoded_bytes = &.{
                0xc4, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
            },
        },
        .{
            .value = .{ .get_tail = .{
                .name = "stream name",
            } },
            .encoded_bytes = &.{
                0xc5, // kind
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
            },
        },
    };

    for (cases) |case| {
        const cmd = case.value;

        const buffer = try testing.allocator.alloc(u8, Command.encodedLength(cmd));
        defer testing.allocator.free(buffer);
        try Command.encode(cmd, buffer);

        try testing.expectEqualSlices(u8, case.encoded_bytes, buffer);

        const cmd2 = try Command.decode(buffer);
        try testing.expectEqualDeep(cmd, cmd2);
    }
}
