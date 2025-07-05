const std = @import("std");
const zimq = @import("zimq");
const io = @import("lio");
const command = io.broker.command;

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    const context: *zimq.Context = try .init();
    defer context.deinit();

    const socket: *zimq.Socket = try .init(context, .dealer);
    defer socket.deinit();

    try socket.connect("tcp://localhost:5555");

    const cmd: command.Command = .{
        .get_tail = .{ .name = "my stream name" },
    };
    const cmd_buf = try cmd.allocEncode(gpa);
    try socket.sendSlice(cmd_buf, .{ .send_more = true });
    gpa.free(cmd_buf);
    try socket.sendSlice("hello", .{ .send_more = true });
    try socket.sendSlice("world", .{ .send_more = false });

    var buffer: zimq.Message = .empty();
    _ = try socket.recvMsg(&buffer, .{});

    std.debug.print("{s}\n", .{buffer.slice()});
}
