const std = @import("std");
const File = std.fs.File;

const cli = @import("cli.zig");
const format = @import("format.zig");
const bech32 = @import("bech32.zig");
const recipient = @import("recipient.zig");

const Args = cli.Args;
const AgeFile = format.AgeFile;
const Key = @import("key.zig").Key;
const Recipient = recipient.Recipient;

pub fn run(args: *Args) !void {
    std.debug.print("encrypt?: {any}\n", .{args.encrypt.flag});
    const file = try std.fs.cwd().openFile("tag.age", .{});
    var buffered_reader = std.io.bufferedReader(file.reader());
    const reader = buffered_reader.reader();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();

    var age = AgeFile(@TypeOf(reader)){
        .allocator = allocator,
        .reader = reader,
    };
    try age.read();

    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    var file_key: Key = blk: {
        for (age.recipients.?) |*r| {
            if (std.mem.eql(u8, r.type.?, Recipient.x25519_recipient_type)) {
                try r.init();
                const file_key = r.unwrap(allocator, identity) catch |err| switch (err) {
                    error.AuthenticationFailed => { continue; },
                    else => return err,
                };
                break :blk try Key.init(allocator, file_key);
            }
        }
        return error.AuthenticationFailed;
    };
    defer file_key.deinit(allocator);

    if (!age.verify_hmac(file_key.key())) {
        std.debug.print("hmac mismatch\n", .{});
    }

    // var plaintext: [4]u8 = undefined;
    // _ = try file_key.AgeDecrypt(&plaintext, age.payload.?);

    var ciphertext = [_]u8{0} ** 37; // TODO: size has to be exact for auth to work
    _ = try file_key.AgeEncrypt(allocator, &ciphertext, "tests");

    var plaintext: [5]u8 = undefined; // TODO: size has to be exact for auth to work
    _ = try file_key.AgeDecrypt(&plaintext, &ciphertext);

    std.debug.print("data: {s}\n", .{plaintext[0..5]});

    for (age.recipients.?) |*r| {
        r.deinit(allocator);
    }
}

test {
    _ = format;
    _ = bech32;
    _ = @import("key.zig");
}
