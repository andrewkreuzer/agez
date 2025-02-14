const std = @import("std");

const lib = @import("lib.zig");
const cli = @import("cli.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer {
        if (gpa.deinit() == .leak) {
            std.debug.print("Leak detected\n", .{});
        }
    }
    defer arena.deinit();

    var args = try cli.args(allocator);
    try lib.run(&args);
}
