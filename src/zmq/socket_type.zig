const std = @import("std");
const mem = std.mem;
const testing = std.testing;

pub const SocketType = enum {
    req,
    rep,
    dealer,
    router,
    @"pub",
    sub,
    xpub,
    xsub,
    push,
    pull,
    client,
    server,

    const names = [_][]const u8{
        "REQ",
        "REP",
        "DEALER",
        "ROUTER",
        "PUB",
        "SUB",
        "XPUB",
        "XSUB",
        "PUSH",
        "PULL",
        "CLIENT",
        "SERVER",
    };

    pub fn validatePeer(self: SocketType, peer: SocketType) !void {
        if (!self.validPeer(peer)) return error.InvalidSocketPeer;
    }

    fn validPeer(self: SocketType, peer: SocketType) bool {
        const valid_peers: []const SocketType = switch (self) {
            .req => &[_]SocketType{ .rep, .router },
            .rep => &[_]SocketType{ .req, .dealer },
            .dealer => &[_]SocketType{ .rep, .dealer, .router },
            .router => &[_]SocketType{ .req, .dealer, .router },
            .sub, .xsub => &[_]SocketType{ .@"pub", .xpub },
            .@"pub", .xpub => &[_]SocketType{ .sub, .xsub },
            .push => &[_]SocketType{.pull},
            .pull => &[_]SocketType{.push},
            .client => &[_]SocketType{.server},
            .server => &[_]SocketType{.client},
        };
        for (valid_peers) |valid_peer|
            if (valid_peer == peer) return true;
        return false;
    }

    pub fn string(self: SocketType) []const u8 {
        return names[@intFromEnum(self)];
    }

    pub fn parse(str: []const u8) !SocketType {
        for (names, 0..) |n, i| {
            if (mem.eql(u8, n, str)) {
                return @as(SocketType, @enumFromInt(i));
            }
        }
        return error.InvalidSocketType;
    }

    test "parse name" {
        for (names) |str| {
            var socket_type = try SocketType.parse(str);
            try testing.expectEqualStrings(str, socket_type.string());
            const str2 = switch (socket_type) {
                .req => "REQ",
                .rep => "REP",
                .dealer => "DEALER",
                .router => "ROUTER",
                .@"pub" => "PUB",
                .xpub => "XPUB",
                .sub => "SUB",
                .xsub => "XSUB",
                .push => "PUSH",
                .pull => "PULL",
                .client => "CLIENT",
                .server => "SERVER",
            };
            try testing.expectEqualStrings(str, str2);
        }
    }

    test validPeer {
        const req = SocketType.req;
        try testing.expect(req.validPeer(.rep));
        try testing.expect(req.validPeer(.router));
        try testing.expect(!req.validPeer(.dealer));
        try testing.expect(SocketType.push.validPeer(.pull));
        try testing.expect(SocketType.pull.validPeer(.push));
        try testing.expect(SocketType.client.validPeer(.server));
    }
};

test {
    _ = SocketType;
}
