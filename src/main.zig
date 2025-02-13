const std = @import("std");

const root = @import("root.zig");
const cli = @import("cli.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer arena.deinit();
    defer {
        if (gpa.deinit() == .leak) {
            std.debug.print("Leak detected\n", .{});
        }
    }

    var args = try cli.args(allocator);
    try root.run(&args);
}

test {
    _  = cli;
}
