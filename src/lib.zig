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
    const file = try std.fs.cwd().openFile("nggyu.webm.age", .{});
    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    const allocator = arena.allocator();

    var age = AgeFile(@TypeOf(reader)){
        .allocator = allocator,
        .r = reader,
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

    var plaintext = std.ArrayList(u8).init(allocator);
    _ = try file_key.ageDecrypt(plaintext.writer(), age.reader());

    // var ciphertext = std.ArrayList(u8).init(allocator);
    // var plaintext_fbs_2 = std.io.fixedBufferStream("yooo");
    // _ = try file_key.ageEncrypt(ciphertext.writer(), plaintext_fbs_2.reader());

    // var plaintext_2 = std.ArrayList(u8).init(allocator);
    // var ciphertext_fbs = std.io.fixedBufferStream(ciphertext.items);
    // _ = try file_key.ageDecrypt(plaintext_2.writer(), ciphertext_fbs.reader());

    // std.debug.print("data: {s}\n", .{plaintext_2.items[0..4]});

    for (age.recipients.?) |*r| {
        r.deinit(allocator);
    }
}

test {
    _  = cli;
    _ = format;
    _ = bech32;
    _ = recipient;
    _ = @import("key.zig");
}
