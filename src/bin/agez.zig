const std = @import("std");
const exit = std.posix.exit;

const lib = @import("lib");
const cli = lib.cli;
const Io = lib.Io;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();
    defer if (gpa.deinit() == .leak) { std.debug.print("Leak detected\n", .{}); };
    defer arena.deinit();

    const args = try cli.args(allocator);
    var io = try Io.init(args);
    defer io.deinit();

    if (args.decrypt.flag()) {
        try lib.decrypt(allocator, &io, args);
    } else {
        try lib.encrypt(allocator, &io, args);
    }
}
