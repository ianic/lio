const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const zmq = @import("protocol.zig");

pub const Record = struct {
    const Self = @This();

    sequence: u64,
    timestamp: u64,

    body: []const u8,
    payload: []const u8,

    pub fn frames(self: Self) zmq.Message.FramesIterator {
        return .init(self.body);
    }

    pub fn parse(payload: []const u8) !Record {
        const msg = zmq.Message{ .payload = payload };
        var iter = msg.frames();

        const control_frame = iter.next() orelse return error.InvalidRecord;
        const control_body = control_frame.body;
        if (control_body.len != 16) return error.InvalidRecord;
        const sequence = mem.readInt(u64, control_body[0..8], .big);
        const timestamp = mem.readInt(u64, control_body[8..16], .big);
        return .{
            .sequence = sequence,
            .timestamp = timestamp,
            .body = payload[control_frame.len..],
            .payload = payload,
        };
    }

    pub fn write(
        allocator: mem.Allocator,
        sequence: u64,
        timestamp: u64,
        body_frames: []const []const u8,
    ) ![]u8 {
        var buf_len: usize = zmq.Frame.length(8 + 8);
        for (body_frames) |f| buf_len += zmq.Frame.length(f.len);
        var buf = try allocator.alloc(u8, buf_len);

        var control_body: [16]u8 = undefined;
        mem.writeInt(u64, control_body[0..8], sequence, .big);
        mem.writeInt(u64, control_body[8..16], timestamp, .big);

        var pos = zmq.Frame.bufWrite(buf, &control_body, body_frames.len > 0).len;
        for (body_frames, 1..) |frm, i| {
            pos += zmq.Frame.bufWrite(buf[pos..], frm, body_frames.len > i).len;
        }
        assert(pos == buf_len);
        return buf;
    }
};

test Record {
    const sequence: u64 = 0x11223344556677;
    const timestamp: u64 = 0x8899aabbccddff;
    const frame1 = "foo";
    const frame2 = "0123456789" ** 26;
    const buf = try Record.write(testing.allocator, sequence, timestamp, &.{ frame1, frame2 });
    defer testing.allocator.free(buf);

    try testing.expectEqual(2 + 16 + 2 + 3 + 9 + 10 * 26, buf.len);

    const r = try Record.parse(buf);
    try testing.expectEqual(sequence, r.sequence);
    try testing.expectEqual(timestamp, r.timestamp);

    var iter = r.frames();
    try testing.expectEqualSlices(u8, frame1, iter.next().?.body);
    try testing.expectEqualSlices(u8, frame2, iter.next().?.body);
}

pub const Kind = enum(u8) {
    // server to client
    // record = 0 // reserved, but record is in the data plane not in control plane
    pos = 1,
    tail,

    // client to server
    append = 0x10,
    seek,
    ack,
    credit,
    get_pos,
    get_tail,
};

pub const EncodeError = error{NoSpaceLeft};

pub const Control = union(Kind) {
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

        pub fn encodedLength(self: Pos) usize {
            return 1 + 4 + 1 + self.name.len + 8 * 4 + 4;
        }
        pub fn encode(self: Pos, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.pos));
            w.int4(self.id);
            w.string(self.name);
            w.int8(self.current.sequence);
            w.int8(self.current.timestamp);
            w.int8(self.tail.sequence);
            w.int8(self.tail.timestamp);
            w.int4(self.credit);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { Pos, usize } {
            var r = BufferReader{ .buffer = buffer };
            var p: Pos = undefined;
            assert(try r.byte() == @intFromEnum(Kind.pos));
            p.id = try r.int4();
            p.name = try r.string();
            p.current.sequence = try r.int8();
            p.current.timestamp = try r.int8();
            p.tail.sequence = try r.int8();
            p.tail.timestamp = try r.int8();
            p.credit = try r.int4();
            return .{ p, r.pos };
        }
    };

    pub const Tail = struct {
        id: u32,
        name: []const u8,
        tail: struct {
            sequence: u64,
            timestamp: u64,
        },

        pub fn encodedLength(self: Tail) usize {
            return 1 + 4 + 1 + self.name.len + 8 * 2;
        }
        pub fn encode(self: Tail, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.tail));
            w.int4(self.id);
            w.string(self.name);
            w.int8(self.tail.sequence);
            w.int8(self.tail.timestamp);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { Tail, usize } {
            var r = BufferReader{ .buffer = buffer };
            var t: Tail = undefined;
            assert(try r.byte() == @intFromEnum(Kind.tail));
            t.id = try r.int4();
            t.name = try r.string();
            t.tail.sequence = try r.int8();
            t.tail.timestamp = try r.int8();
            return .{ t, r.pos };
        }
    };

    pub const Append = struct {
        stream_name: []const u8,
        record: Record,

        // pub fn encodedLength(self: Append) usize {}
        // pub fn encode(self: Append, buffer: []u8) EncodeError!usize {}
        // pub fn decode(buffer: []const u8) EncodeError!struct { Append, usize } {}
    };

    pub const Seek = struct {
        id: u32,
        sequence: u64,
        timestamp: u64,

        pub fn encodedLength(self: Seek) usize {
            _ = self;
            return 1 + 4 + 8 * 2;
        }
        pub fn encode(self: Seek, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.seek));
            w.int4(self.id);
            w.int8(self.sequence);
            w.int8(self.timestamp);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { Seek, usize } {
            var r = BufferReader{ .buffer = buffer };
            var s: Seek = undefined;
            assert(try r.byte() == @intFromEnum(Kind.seek));
            s.id = try r.int4();
            s.sequence = try r.int8();
            s.timestamp = try r.int8();
            return .{ s, r.pos };
        }
    };

    pub const Ack = struct {
        id: u32,
        sequence: u64,

        pub fn encodedLength(self: Ack) usize {
            _ = self;
            return 1 + 4 + 8;
        }
        pub fn encode(self: Ack, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.ack));
            w.int4(self.id);
            w.int8(self.sequence);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { Ack, usize } {
            var r = BufferReader{ .buffer = buffer };
            var a: Ack = undefined;
            assert(try r.byte() == @intFromEnum(Kind.ack));
            a.id = try r.int4();
            a.sequence = try r.int8();
            return .{ a, r.pos };
        }
    };

    pub const Credit = struct {
        id: u32,
        credit: u32,

        pub fn encodedLength(self: Credit) usize {
            _ = self;
            return 1 + 4 + 4;
        }
        pub fn encode(self: Credit, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.credit));
            w.int4(self.id);
            w.int4(self.credit);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { Credit, usize } {
            var r = BufferReader{ .buffer = buffer };
            var c: Credit = undefined;
            assert(try r.byte() == @intFromEnum(Kind.credit));
            c.id = try r.int4();
            c.credit = try r.int4();
            return .{ c, r.pos };
        }
    };

    pub const GetPos = struct {
        id: u32,

        pub fn encodedLength(self: GetPos) usize {
            _ = self;
            return 1 + 4;
        }
        pub fn encode(self: GetPos, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.get_pos));
            w.int4(self.id);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { GetPos, usize } {
            var r = BufferReader{ .buffer = buffer };
            var p: GetPos = undefined;
            assert(try r.byte() == @intFromEnum(Kind.get_pos));
            p.id = try r.int4();
            return .{ p, r.pos };
        }
    };

    pub const GetTail = struct {
        name: []const u8,

        pub fn encodedLength(self: GetTail) usize {
            return 1 + 1 + self.name.len;
        }
        pub fn encode(self: GetTail, buffer: []u8) EncodeError!usize {
            if (buffer.len < self.encodedLength()) return error.NoSpaceLeft;
            var w = BufferWriter{ .buffer = buffer };
            w.byte(@intFromEnum(Kind.get_tail));
            w.string(self.name);
            return w.pos;
        }
        pub fn decode(buffer: []const u8) EncodeError!struct { GetTail, usize } {
            var r = BufferReader{ .buffer = buffer };
            var p: GetTail = undefined;
            assert(try r.byte() == @intFromEnum(Kind.get_tail));
            p.name = try r.string();
            return .{ p, r.pos };
        }
    };

    pos: Pos,
    tail: Tail,

    append: Append,
    seek: Seek,
    ack: Ack,
    credit: Credit,
    get_pos: GetPos,
    get_tail: GetTail,
};

test "Pos encode/decode" {
    const p = Control.Pos{
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
    };

    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, p.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try p.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);

        // for (buf) |b| std.debug.print(", 0x{x}", .{b});
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x35,
                0x1, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // current.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0, // current.timestamp
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // tail.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // tail timestamp
                0xdd, 0xee, 0xaa, 0xdd, // credit
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const p2, _ = try Control.Pos.decode(frm.body);
        try testing.expectEqualDeep(p, p2);
    }
}

test "Tail encode/decode" {
    const t = Control.Tail{
        .id = 0xaabbccdd,
        .name = "stream name",
        .tail = .{
            .sequence = 0x1122334455667788 + 1,
            .timestamp = 0x99aabbccddeeff00 + 1,
        },
    };
    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, t.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try t.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x21, // zmq header
                0x2, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // tail.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // tail timestamp
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const t2, _ = try Control.Tail.decode(frm.body);
        try testing.expectEqualDeep(t, t2);
    }
}

test "Seek encode/decode" {
    const s = Control.Seek{
        .id = 0xaabbccdd,
        .sequence = 0x1122334455667788 + 1,
        .timestamp = 0x99aabbccddeeff00 + 1,
    };
    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, s.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try s.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x15, // zmq header
                0x11, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // timestamp
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const s2, _ = try Control.Seek.decode(frm.body);
        try testing.expectEqualDeep(s, s2);
    }
}

test "Ack encode/decode" {
    const a = Control.Ack{
        .id = 0xaabbccdd,
        .sequence = 0x1122334455667788 + 1,
    };
    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, a.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try a.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x0d, // zmq header
                0x12, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // sequence
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const a2, _ = try Control.Ack.decode(frm.body);
        try testing.expectEqualDeep(a, a2);
    }
}

test "Credit encode/decode" {
    const c = Control.Credit{
        .id = 0xaabbccdd,
        .credit = 0x11223344,
    };
    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, c.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try c.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x09, // zmq header
                0x13, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0x11, 0x22, 0x33, 0x44, // credit
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const c2, _ = try Control.Credit.decode(frm.body);
        try testing.expectEqualDeep(c, c2);
    }
}

test "GetPos encode/decode" {
    const p = Control.GetPos{
        .id = 0xaabbccdd,
    };
    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, p.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try p.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x05, // zmq header
                0x14, // kind
                0xaa, 0xbb, 0xcc, 0xdd, // id
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const p2, _ = try Control.GetPos.decode(frm.body);
        try testing.expectEqualDeep(p, p2);
    }
}

test "GetTail encode/decode" {
    const t = Control.GetTail{
        .name = "stream name",
    };
    // allocate buffer for zmq header and data body
    const frame_buf, var pos = try zmq.Frame.alloc(testing.allocator, t.encodedLength());
    defer testing.allocator.free(frame_buf);
    { // encode body
        pos += try t.encode(frame_buf[pos..]);
        try testing.expectEqual(pos, frame_buf.len);
        try testing.expectEqualSlices(
            u8,
            &.{
                0x0, 0x0d, // zmq header
                0x15, // kind
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
            },
            frame_buf,
        );
    }
    { // decode frame
        const msg = zmq.Message{ .payload = frame_buf };
        var iter = msg.frames();
        const frm = iter.next().?;

        const t2, _ = try Control.GetTail.decode(frm.body);
        try testing.expectEqualDeep(t, t2);
    }
}

const BufferWriter = struct {
    const Self = @This();

    buffer: []u8,
    pos: usize = 0,

    pub fn byte(self: *Self, b: u8) void {
        self.buffer[self.pos] = b;
        self.pos += 1;
    }

    pub fn int4(self: *Self, i: u32) void {
        mem.writeInt(u32, self.buffer[self.pos..][0..4], i, .big);
        self.pos += 4;
    }

    pub fn int8(self: *Self, i: u64) void {
        mem.writeInt(u64, self.buffer[self.pos..][0..8], i, .big);
        self.pos += 8;
    }

    pub fn string(self: *Self, s: []const u8) void {
        assert(s.len <= 0xff);
        self.byte(@intCast(s.len));
        @memcpy(self.buffer[self.pos..][0..s.len], s);
        self.pos += s.len;
    }

    pub fn encode(self: *Self, value: anytype) void {
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

    pub fn encodedLength(value: anytype) usize {
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

    pub fn content(self: Self) []u8 {
        return self.buffer[0..self.pos];
    }
};

const BufferReader = struct {
    const Self = @This();

    buffer: []const u8,
    pos: usize = 0,

    const Error = error{NoSpaceLeft};

    pub fn byte(self: *Self) Error!u8 {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += 1;
        return self.buffer[self.pos];
    }

    pub fn int4(self: *Self) Error!u32 {
        if (self.pos + 4 > self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += 4;
        return mem.readInt(u32, self.buffer[self.pos..][0..4], .big);
    }

    pub fn int8(self: *Self) Error!u64 {
        if (self.pos + 8 > self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += 8;
        return mem.readInt(u64, self.buffer[self.pos..][0..8], .big);
    }

    pub fn string(self: *Self) Error![]const u8 {
        const len = try self.byte();
        if (self.pos + len > self.buffer.len) return error.NoSpaceLeft;
        defer self.pos += len;
        return self.buffer[self.pos..][0..len];
    }

    pub fn decodeInto(self: *Self, ptr: anytype) Error!void {
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

    pub fn decode(self: *Self, T: type) Error!T {
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

test "reflection" {
    const value = Control.Pos{
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
    };

    const buffer_len = BufferWriter.encodedLength(value);
    try testing.expectEqual(52, buffer_len);
    const buffer = try testing.allocator.alloc(u8, buffer_len);
    defer testing.allocator.free(buffer);

    { // encode
        var w = BufferWriter{ .buffer = buffer };
        w.encode(value);
        try testing.expectEqual(buffer_len, w.pos);

        try testing.expectEqualSlices(
            u8,
            &.{
                0xaa, 0xbb, 0xcc, 0xdd, // id
                0xb, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x6e, 0x61, 0x6d, 0x65, // name
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // current.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0, // current.timestamp
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, // tail.sequence
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x1, // tail timestamp
                0xdd, 0xee, 0xaa, 0xdd, // credit
            },
            buffer,
        );
    }
    { // decode
        var r = BufferReader{ .buffer = buffer };
        const p = try r.decode(Control.Pos);
        try testing.expectEqualDeep(value, p);
    }
    { // decodeInto
        var p: Control.Pos = undefined;
        var r = BufferReader{ .buffer = buffer };
        try r.decodeInto(&p);
        try testing.expectEqualDeep(value, p);
    }
}
