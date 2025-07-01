const std = @import("std");
const zimq = @import("zimq");

pub fn main() !void {
    const context: *zimq.Context = try .init();
    defer context.deinit();

    const socket: *zimq.Socket = try .init(context, .dealer);
    defer socket.deinit();

    try socket.connect("tcp://localhost:5555");

    try socket.sendSlice("hello", .{ .send_more = true });
    try socket.sendSlice("world", .{ .send_more = false });

    var buffer: zimq.Message = .empty();
    _ = try socket.recvMsg(&buffer, .{});

    std.debug.print("{s}\n", .{buffer.slice()});
}
