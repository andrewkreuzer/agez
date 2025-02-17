const std = @import("std");
const Allocator = std.mem.Allocator;
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;
const File = std.fs.File;

const bech32 = @import("bech32.zig");
const cli = @import("cli.zig");
const format = @import("format.zig");
const Io = @import("io.zig");
const recipient = @import("recipient.zig");

const Args = cli.Args;
const AgeFile = format.AgeFile;
const Key = @import("key.zig").Key;
const Recipient = recipient.Recipient;

pub fn encrypt(
    allocator: Allocator,
    io: *Io,
    args: Args
) !void {
    _ = allocator;
    _ = io;
    _ = args;
    return undefined;
}

pub fn decrypt(
    allocator: Allocator,
    io: *Io,
    args: Args
) !void {
    const reader = io.reader();
    const writer = io.writer();

    var age = AgeFile(@TypeOf(reader)){
        .allocator = allocator,
        .r = reader,
    };
    try age.read();

    var identity_buf = [_]u8{0} ** 90;
    const identity = try Io.identity(&identity_buf, args);
    defer std.crypto.utils.secureZero(u8, identity);

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

    _ = try file_key.ageDecrypt(writer, age.reader());

    for (age.recipients.?) |*r| {
        r.deinit(allocator);
    }
}

const Error = error {
    MissingIdentity,
};

test {
    _  = cli;
    _ = format;
    _ = bech32;
    _ = recipient;
    _ = @import("key.zig");
}
