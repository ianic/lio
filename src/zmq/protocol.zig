const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;

pub const SocketType = @import("socket_type.zig").SocketType;

pub const Parser = struct {
    const Self = @This();

    buffer: []const u8,
    pos: usize = 0,

    pub fn traffic(self: *Parser) !?Traffic {
        var rdr = self.reader();
        var frm = try rdr.frame() orelse return null;
        // Command is always single frame.
        if (frm.flags.command) {
            const cmd = try Command.parse(frm) orelse return null;
            self.pos += frm.len;
            return .{ .command = cmd };
        }
        // Collect all message frames.
        var data_pos: usize = 0;
        while (frm.flags.more) {
            frm = try rdr.frame() orelse return null;
            if (frm.body.len == 0 and data_pos == 0) data_pos = rdr.pos;
            if (frm.flags.command) return error.InvalidFragmentation;
        }

        defer self.pos += rdr.pos;
        return .{
            .message = .{
                .payload = self.buffer[self.pos..][0..rdr.pos],
                .data_pos = data_pos,
            },
        };
    }

    pub fn unparsed(self: Parser) []const u8 {
        return self.buffer[self.pos..];
    }

    pub fn greeting(self: *Self) !?Greeting {
        const grt = try Greeting.parse(self.buffer) orelse return null;
        self.pos += Greeting.len;
        return grt;
    }

    pub fn ready(self: *Self) !?Command.Ready {
        var rdr = self.reader();
        const frm = try rdr.frame() orelse return null;
        const rdy = try Command.Ready.parse(frm) orelse return null;
        self.pos += frm.len;
        return rdy;
    }

    pub fn handshake(self: *Self) !?Handshake {
        var rdr = self.reader();
        const grt_buf = rdr.slice(Greeting.len) orelse return null;
        const grt = try Greeting.parse(grt_buf) orelse return null;
        const frm = try rdr.frame() orelse return null;
        const rdy = try Command.Ready.parse(frm) orelse return null;
        self.pos += rdr.pos;
        return .{ .greeting = grt, .ready = rdy };
    }

    fn reader(self: *Self) Reader {
        return .{ .buffer = self.buffer[self.pos..] };
    }

    fn command(self: *Self) !?Command {
        var rdr = self.reader();
        const frm = rdr.frame() orelse return null;
        const cmd = try Command.parse(frm) orelse return null;
        self.pos += frm.len;
        return cmd;
    }
};

pub const Traffic = union(enum) {
    command: Command,
    message: Message,
};

pub const Handshake = struct {
    greeting: Greeting,
    ready: Command.Ready,
};

pub const Frame = struct {
    flags: Flags,
    body: []const u8, // body part, without header (flags, len)
    len: u64, // complete frame len (header + body)

    pub fn bufWrite(buf: []u8, data: []const u8, more: bool) []u8 {
        const pos = writeHeader(buf, data.len, more);
        @memcpy(buf[pos..][0..data.len], data);
        return buf[0 .. pos + data.len];
    }

    fn writeHeader(buf: []u8, data_len: usize, more: bool) usize {
        const flags = Flags{ .more = more, .long = data_len > 0xff, .command = false };
        buf[0] = @bitCast(flags);
        if (flags.long)
            mem.writeInt(u64, buf[1..9], data_len, .big)
        else
            buf[1] = @intCast(data_len);
        const pos: usize = if (flags.long) 9 else 2;
        return pos;
    }

    pub fn length(data_len: usize) usize {
        if (data_len > 0xff) return data_len + 9;
        return data_len + 2;
    }

    /// Allocate buffer for whole frame, write frame header. Return frame buffer
    /// and header len (position where to write body).
    ///
    /// Buffer inside stream is owned by caller.
    pub fn alloc(allocator: mem.Allocator, data_len: usize) !struct { []u8, usize } {
        const frame_len = Frame.length(data_len);
        const buf = try allocator.alloc(u8, frame_len);
        const pos = writeHeader(buf, data_len, false);
        return .{ buf, pos };
    }
};

pub const Greeting = struct {
    minor: u8,
    major: u8,
    security_mechanism: []const u8,
    is_server: bool,

    const len = 64;

    fn parse(buf: []const u8) !?Greeting {
        if (buf.len < Greeting.len) return null;
        if (buf[0] != 0xff or buf[9] != 0x7f) return error.InvalidGreetingSignature;
        for (33..64) |i| if (buf[i] != 0) return error.InvalidGreetingFiller;
        return .{
            .major = buf[10],
            .minor = buf[11],
            .security_mechanism = std.mem.trimRight(u8, buf[12..32], &[_]u8{0}),
            .is_server = buf[32] == 1,
        };
    }
};

pub const Command = union(enum) {
    ready: Ready,
    err: []const u8, // reason
    subscribe: []const u8, //subscription
    cancel: []const u8, //subscription
    ping: struct {
        ttl: u16,
        context: []const u8,
    },
    pong: struct {
        context: []const u8,
    },

    const Ready = struct {
        socket_type: SocketType,
        metadata: []const u8,
        identity: []const u8 = &.{},
        resource: []const u8 = &.{},

        fn parse(frm: Frame) !?Ready {
            var rdr = Reader{ .buffer = frm.body };
            if (!mem.eql(u8, "READY", rdr.key() orelse return null)) return error.InvalidCommand;
            var cmd = Ready{
                .socket_type = undefined,
                .metadata = frm.body[rdr.pos..],
            };
            var found_socket_type: bool = false;
            while (rdr.key()) |key| {
                const value = rdr.value() orelse return null;
                if (std.ascii.eqlIgnoreCase("Socket-Type", key)) {
                    cmd.socket_type = try SocketType.parse(value);
                    found_socket_type = true;
                }
                if (std.ascii.eqlIgnoreCase("Identity", key)) {
                    cmd.identity = value;
                }
                if (std.ascii.eqlIgnoreCase("Resource", key)) {
                    cmd.resource = value;
                }
            }
            if (!found_socket_type) return error.InvalidSocketType;
            return cmd;
        }
    };

    fn parse(frm: Frame) !?Command {
        var rdr = Reader{ .buffer = frm.body };
        const name = rdr.key() orelse return null;
        if (mem.eql(u8, "SUBSCRIBE", name))
            return .{
                .subscribe = rdr.unparsed(),
            }
        else if (mem.eql(u8, "CANCEL", name))
            return .{
                .cancel = rdr.unparsed(),
            }
        else if (mem.eql(u8, "ERROR", name))
            return .{
                .err = rdr.key() orelse &.{},
            }
        else if (mem.eql(u8, "PING", name)) {
            const buf = rdr.unparsed();
            if (buf.len < 2 or buf.len > 18) return error.InvalidCommand;
            return .{
                .ping = .{
                    .ttl = mem.readInt(u16, buf[0..2], .big),
                    .context = buf[2..],
                },
            };
        } else if (mem.eql(u8, "PONG", name)) {
            const buf = rdr.unparsed();
            if (buf.len > 16) return error.InvalidCommand;
            return .{
                .pong = .{
                    .context = buf,
                },
            };
        } else return error.UnknownCommand;
    }
};

pub const Message = struct {
    const Self = @This();

    payload: []const u8,
    data_pos: usize = 0,

    pub fn envelope(self: Self) []const u8 {
        return self.payload[0..self.data_pos];
    }

    pub fn frames(self: Self) FramesIterator {
        return FramesIterator{ .rdr = Reader{ .buffer = self.payload } };
    }

    pub fn dataFrames(self: Self) FramesIterator {
        return FramesIterator{ .rdr = Reader{ .buffer = self.payload[self.data_pos..] } };
    }

    pub const FramesIterator = struct {
        rdr: Reader,

        pub fn init(payload: []const u8) FramesIterator {
            return .{ .rdr = Reader{ .buffer = payload } };
        }

        pub fn next(self: *FramesIterator) ?Frame {
            return self.rdr.frame() catch unreachable;
        }
    };
};

pub const Flags = packed struct {
    /// bit 0, more frames to follow
    more: bool,
    /// bit 1, frames size is u8 (0) or u64 (1)
    long: bool,
    /// bit 2, this is command frame
    command: bool,
    /// bits 7-3, reserved, must be 0
    _reserved: u5 = 0,

    test "parse" {
        var f: Flags = @bitCast(@as(u8, 2));
        try testing.expect(!f.more);
        try testing.expect(f.long);
        try testing.expect(f._reserved == 0);

        f = @bitCast(@as(u8, 3));
        try testing.expect(!f.command);
        try testing.expect(f.more);
        try testing.expect(f.long);
        try testing.expect(f._reserved == 0);

        f = @bitCast(@as(u8, 6));
        try testing.expect(f.command);
        try testing.expect(f.long);
        try testing.expect(f._reserved == 0);
    }
};

const Reader = struct {
    const Self = @This();

    buffer: []const u8,
    pos: usize = 0,

    // 1 bytes size + data
    fn key(self: *Self) ?[]const u8 {
        var buf = self.buffer[self.pos..];
        if (buf.len < 1) return null;
        const size: usize = @intCast(buf[0]);
        buf = buf[1..];
        if (buf.len < size) return null;
        self.pos += 1 + size;
        return buf[0..size];
    }

    // 4 bytes size + data
    fn value(self: *Self) ?[]const u8 {
        var buf = self.buffer[self.pos..];
        if (buf.len < 4) return null;
        const size = mem.readInt(u32, buf[0..4], .big);
        buf = buf[4..];
        if (buf.len < size) return null;
        self.pos += 4 + size;
        return buf[0..size];
    }

    fn slice(self: *Self, len: usize) ?[]const u8 {
        var buf = self.buffer[self.pos..];
        if (buf.len < len) return null;
        self.pos += len;
        return buf[0..len];
    }

    fn unparsed(self: Self) []const u8 {
        return self.buffer[self.pos..];
    }

    fn frame(self: *Self) !?Frame {
        const buf = self.buffer[self.pos..];
        if (buf.len < 2) return null;
        const flags: Flags = @bitCast(buf[0]);
        if (flags._reserved != 0) return error.ReservedFlagsBits;

        if (flags.long and buf.len < 9) return null;
        const payload_len: u64 = if (flags.long)
            mem.readInt(u64, buf[1..][0..8], .big)
        else
            @intCast(buf[1]);
        const payload_head: usize = if (flags.long) 1 + 8 else 1 + 1;
        const len = payload_head + payload_len;
        if (buf.len < len) return null;
        self.pos += len;
        return .{
            .flags = flags,
            .body = buf[payload_head..][0..payload_len],
            .len = len,
        };
    }
};

test {
    _ = Flags;
    _ = @import("socket_type.zig");
}

const hexToBytes = @import("testu.zig").hexToBytes;

test "Parser.frame" {
    var rdr = Reader{ .buffer = &testdata.greeting };
    try testing.expectError(error.ReservedFlagsBits, rdr.frame());

    rdr = Reader{ .buffer = &testdata.ready };
    const frm = (try rdr.frame()).?;
    try testing.expect(frm.flags.command);
    try testing.expect(!frm.flags.long);
    try testing.expect(!frm.flags.more);
    try testing.expectEqual(0x26, frm.body.len);
}

test "Parser.greeting" {
    // Not enough data, Parser.next returns null
    for (0..testdata.greeting.len) |i| {
        const buf = testdata.greeting[0..i];
        var p = Parser{ .buffer = buf };
        try testing.expect(try p.greeting() == null);
        try testing.expectEqual(0, p.pos);
        try testing.expectEqualSlices(u8, buf, p.unparsed());
    }
    // Full greeting
    var p = Parser{ .buffer = &testdata.greeting ++ "_unparsed_" };
    const gr = (try p.greeting()).?;
    try testing.expectEqual(3, gr.major);
    try testing.expectEqual(1, gr.minor);
    try testing.expectEqualStrings("NULL", gr.security_mechanism);
    try testing.expectEqual(false, gr.is_server);
    try testing.expectEqual(64, p.pos);
    try testing.expectEqual(10, p.unparsed().len);
}

test "Parser.ready" {
    for (0..testdata.ready.len) |i| {
        const buf = testdata.ready[0..i];
        var p = Parser{ .buffer = buf };
        try testing.expect(try p.ready() == null);
        try testing.expectEqual(0, p.pos);
        try testing.expectEqualSlices(u8, buf, p.unparsed());
    }
    {
        var p = Parser{ .buffer = &testdata.ready ++ "_unparsed_" };
        const rdy = (try p.ready()).?;
        try testing.expectEqual(.req, rdy.socket_type);
        try testing.expectEqual(50, p.buffer.len);
        try testing.expectEqual(40, p.pos);
        try testing.expectEqual(10, p.unparsed().len);
    }
    {
        var p = Parser{ .buffer = &testdata.ready_with_identity ++ "_unparsed_" };
        const rdy = (try p.ready()).?;
        try testing.expectEqual(.rep, rdy.socket_type);
        try testing.expectEqualStrings("Pero Zdero", rdy.identity);
        try testing.expectEqual(60, p.buffer.len);
        try testing.expectEqual(50, p.pos);
        try testing.expectEqual(10, p.unparsed().len);
    }
}

test "Parser.handshake" {
    var hs_buf = testdata.greeting ++ testdata.ready_with_identity;
    // Partial buffer
    for (0..hs_buf.len) |i| {
        const buf = hs_buf[0..i];
        var p = Parser{ .buffer = buf };
        try testing.expect(try p.handshake() == null);
        try testing.expectEqual(0, p.pos);
        try testing.expectEqualSlices(u8, buf, p.unparsed());
    }
    // Full handshake + some more data
    var p = Parser{ .buffer = &hs_buf ++ "012345678901" };
    const hs = (try p.handshake()).?;

    const gr = hs.greeting;
    try testing.expectEqual(3, gr.major);
    try testing.expectEqual(1, gr.minor);
    try testing.expectEqualStrings("NULL", gr.security_mechanism);
    try testing.expectEqual(false, gr.is_server);

    const rdy = hs.ready;
    try testing.expectEqual(.rep, rdy.socket_type);
    try testing.expectEqualStrings("Pero Zdero", rdy.identity);

    try testing.expectEqual(114, p.pos);
    try testing.expectEqual(12, p.unparsed().len);
}

test "Parser.message" {
    var msg_data = testdata.has_more_small ++
        testdata.separator ++
        testdata.last_big;
    try testing.expectEqual(283, msg_data.len);

    var p = Parser{ .buffer = &msg_data ++ "_unparsed_" };
    const msg = (try p.traffic()).?.message;
    try testing.expectEqual(283, msg.payload.len);
    try testing.expectEqual(293, p.buffer.len);
    try testing.expectEqual(283, p.pos);
    try testing.expectEqual(10, p.unparsed().len);
    try testing.expectEqual(14, msg.data_pos);
    try testing.expectEqualSlices(u8, &testdata.has_more_small ++ testdata.separator, msg.envelope());
    {
        var iter = msg.dataFrames();
        const frm = iter.next().?;
        try testing.expectEqual(testdata.last_big.len, frm.len);
        try testing.expectEqualSlices(u8, &testdata.big_body, frm.body);
        try testing.expect(iter.next() == null);
    }
    {
        var iter = msg.frames();
        try testing.expectEqualSlices(u8, testdata.has_more_small[2..], iter.next().?.body);
        try testing.expectEqualSlices(u8, testdata.separator[2..], iter.next().?.body);
        try testing.expectEqualSlices(u8, &testdata.big_body, iter.next().?.body);
        try testing.expect(iter.next() == null);
    }
}

const testdata = struct {
    const greeting = hexToBytes(
        \\ ff 00 00 00 00 00 00 00 01 7f 03 01 4e 55 4c 4c
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    );
    // command: ready, Socket-Type: REQ, Identity: ""
    const ready = hexToBytes(
        \\ 04 26 05 52 45 41 44 59 0b 53 6f 63 6b 65 74 2d
        \\ 54 79 70 65 00 00 00 03 52 45 51 08 49 64 65 6e
        \\ 74 69 74 79 00 00 00 00
    );
    // command: ready, Socket-Type: REP, Identity: "Pero Zdero"
    const ready_with_identity = hexToBytes(
        \\ 04 30 05 52 45 41 44 59 0b 53 6f 63 6b 65 74 2d
        \\ 54 79 70 65 00 00 00 03 52 45 50 08 49 64 65 6e
        \\ 74 69 74 79 00 00 00 0a 50 65 72 6f 20 5a 64 65
        \\ 72 6f
    );

    // empty frame (has_more = true, size = 0)
    const separator = hexToBytes(
        \\ 01 00
    );
    // (has_more = false, size = 10)
    const last_small = hexToBytes(
        \\ 00 0a 30 31 32 33 34 35 36 37 38 39
    );
    // (has_more = true, size = 10)
    const has_more_small = hexToBytes(
        \\ 01 0a 30 31 32 33 34 35 36 37 38 39
    );
    // (has_more = true, long_size = true, size = 260)
    const has_more_big = hexToBytes(
        \\ 03 00 00 00 00 00 00 01 04
    ) ++ big_body;
    // (has_more = false, long_size = true, size = 260)
    const last_big = hexToBytes(
        \\ 02 00 00 00 00 00 00 01 04
    ) ++ big_body;
    const big_body = hexToBytes(
        \\ 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35
        \\ 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31
        \\ 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37
        \\ 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33
        \\ 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39
        \\ 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35
        \\ 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31
        \\ 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37
        \\ 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33
        \\ 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39
        \\ 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35
        \\ 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31
        \\ 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37
        \\ 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33
        \\ 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39
        \\ 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35
        \\ 36 37 38 39
    );
};

/// Returns greeting and ready messages.
pub fn handshake(
    allocator: mem.Allocator,
    socket_type: SocketType,
    identity: []const u8,
) ![]u8 {
    // major: 3, minor: 1, security machanism: NULL, is server: false
    const greeting = hexToBytes(
        \\ ff 00 00 00 00 00 00 00 01 7f 03 01 4e 55 4c 4c
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    );
    const ready = "\x05READY"; // 1 bytes is string size, then string
    const socket_type_key = "\x0bSocket-Type";
    const identity_key = "\x08Identity";
    const socket_type_name = socket_type.string();

    const size: u64 =
        ready.len +
        socket_type_key.len + 4 + socket_type_name.len +
        if (identity.len == 0) 0 else identity_key.len + 4 + identity.len;
    const is_long_size = size > 255;
    const ready_frame_len: usize = if (is_long_size) 1 + 8 + size else 1 + 1 + size;

    const buf = try allocator.alloc(u8, greeting.len + ready_frame_len);
    var fbs = std.io.fixedBufferStream(buf);
    var w = fbs.writer();

    try w.writeAll(&greeting);
    try w.writeByte(0x04);
    if (is_long_size)
        try w.writeInt(u64, size, .big)
    else
        try w.writeByte(@intCast(size));
    try w.writeAll(ready);
    try w.writeAll(socket_type_key);
    try w.writeInt(u32, @intCast(socket_type_name.len), .big);
    try w.writeAll(socket_type_name);
    if (identity.len > 0) {
        try w.writeAll(identity_key);
        try w.writeInt(u32, @intCast(identity.len), .big);
        try w.writeAll(identity);
    }

    return buf;
}

test "handshake create" {
    {
        const expected = hexToBytes(
            // greeting
            \\ ff 00 00 00 00 00 00 00 01 7f 03 01 4e 55 4c 4c
            \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            \\ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            // ready, socket-type: rep
            \\ 04 19 05 52 45 41 44 59 0b 53 6f 63 6b 65 74 2d
            \\ 54 79 70 65 00 00 00 03 52 45 50
        );
        const actual = try handshake(testing.allocator, .rep, &.{});
        defer testing.allocator.free(actual);
        try testing.expectEqualSlices(u8, &expected, actual);
    }
    {
        const actual = try handshake(testing.allocator, .rep, "localhost");
        defer testing.allocator.free(actual);
        const header = "\x04\x2f\x05READY";
        try testing.expectEqualSlices(u8, header, actual[64..][0..header.len]);
        const socket_type_kv = "\x0bSocket-Type\x00\x00\x00\x03REP";
        try testing.expectEqualSlices(u8, socket_type_kv, actual[64 + 8 ..][0..socket_type_kv.len]);
        const identity_kv = "\x08Identity\x00\x00\x00\x09localhost";
        try testing.expectEqualSlices(u8, identity_kv, actual[actual.len - identity_kv.len ..]);
    }
}

pub const ping = "\x04\x07\x04PING\x00\x00";

pub fn pong(buf: []u8, context: []const u8) []const u8 {
    assert(context.len <= 16);
    assert(buf.len >= 7 + context.len);
    @memcpy(buf[0..7], "\x04\x05\x04PONG");
    if (context.len == 0)
        return buf[0..7];
    @memcpy(buf[7..][0..context.len], context);
    buf[1] += @intCast(context.len);
    return buf[0 .. 7 + context.len];
}

test "pong" {
    var buf: [23]u8 = undefined;
    {
        var p = Parser{ .buffer = pong(&buf, &.{}) };
        const pg = (try p.traffic()).?.command.pong;
        try testing.expectEqual(0, pg.context.len);
    }
    {
        var p = Parser{ .buffer = pong(&buf, "0123456789") };
        const pg = (try p.traffic()).?.command.pong;
        try testing.expectEqualStrings("0123456789", pg.context);
    }
}
