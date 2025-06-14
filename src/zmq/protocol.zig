const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const SocketType = @import("main.zig").SocketType;

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
            if (frm.payload.len == 0 and data_pos == 0) data_pos = rdr.pos;
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

const Traffic = union(enum) {
    command: Command,
    message: Message,
};

const Frame = struct {
    flags: Flags,
    payload: []const u8,
    len: u64,
};

const Greeting = struct {
    minor: u8,
    major: u8,
    security_mechanism: []const u8,
    is_server: bool,

    const len = 64;

    pub fn parse(buf: []const u8) !?Greeting {
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

const Command = union(enum) {
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
            var rdr = Reader{ .buffer = frm.payload };
            if (!mem.eql(u8, "READY", rdr.key() orelse return null)) return error.InvalidCommand;
            var cmd = Ready{
                .socket_type = undefined,
                .metadata = frm.payload[rdr.pos..],
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
        var rdr = Reader{ .buffer = frm.payload };
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

    pub fn frames(self: Self) Frames {
        return Frames{ .rdr = Reader{ .buffer = self.payload } };
    }

    pub fn dataFrames(self: Self) Frames {
        return Frames{ .rdr = Reader{ .buffer = self.payload[self.data_pos..] } };
    }

    pub const Frames = struct {
        rdr: Reader,

        pub fn next(self: *Frames) ?Frame {
            return self.rdr.frame() catch unreachable;
        }
    };
};

const Flags = packed struct {
    /// bit 0, more frames to follow
    more: bool,
    /// bit 1, frames size is u8 (0) or u64 (1)
    long: bool,
    /// bit 2, this is command frame
    command: bool,
    /// bits 7-3, reserved, must be 0
    _reserved: u5,

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
    fn value(self: anytype) ?[]const u8 {
        var buf = self.buffer[self.pos..];
        if (buf.len < 4) return null;
        const size = mem.readInt(u32, buf[0..4], .big);
        buf = buf[4..];
        if (buf.len < size) return null;
        self.pos += 4 + size;
        return buf[0..size];
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
            .payload = buf[payload_head..][0..payload_len],
            .len = len,
        };
    }
};

test {
    _ = Flags;
    _ = @import("main.zig");
}

const hexToBytes = @import("main.zig").hexToBytes;

test "Parser.frame" {
    var rdr = Reader{ .buffer = &testdata.greeting };
    try testing.expectError(error.ReservedFlagsBits, rdr.frame());

    rdr = Reader{ .buffer = &testdata.ready };
    const frm = (try rdr.frame()).?;
    try testing.expect(frm.flags.command);
    try testing.expect(!frm.flags.long);
    try testing.expect(!frm.flags.more);
    try testing.expectEqual(0x26, frm.payload.len);
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

test "Parse.message" {
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
        try testing.expectEqualSlices(u8, &testdata.big_body, frm.payload);
        try testing.expect(iter.next() == null);
    }
    {
        var iter = msg.frames();
        try testing.expectEqualSlices(u8, testdata.has_more_small[2..], iter.next().?.payload);
        try testing.expectEqualSlices(u8, testdata.separator[2..], iter.next().?.payload);
        try testing.expectEqualSlices(u8, &testdata.big_body, iter.next().?.payload);
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
