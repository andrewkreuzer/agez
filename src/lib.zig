const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const File = std.fs.File;

pub const bech32 = @import("bech32.zig");
pub const cli = @import("cli.zig");
pub const Io = @import("io.zig");
pub const Key = @import("key.zig").Key;
pub const Recipient = @import("recipient.zig").Recipient;
pub const X25519 = @import("X25519.zig");
pub const ssh = @import("ssh/lib.zig");

const armor = @import("armor.zig");
const format = @import("format.zig");
const _age = @import("age.zig");
const Age = _age.Age;
const ageEncrypt = _age.ageEncrypt;
const ageDecrypt = _age.ageDecrypt;
const AgeReader = format.AgeReader;
const AgeWriter = format.AgeWriter;
const Args = cli.Args;

pub fn encrypt(
    allocator: Allocator,
    io: *Io,
    file_key: Key,
    recipients: ArrayList(Recipient),
    armored: bool,
) !void {
    const reader = io.reader();
    const writer = io.writer();

    const age: Age = .{
        .version = .v1,
        .recipients = recipients,
    };
    var age_writer = AgeWriter(@TypeOf(writer)).init(allocator, writer, armored);
    try age_writer.write(&file_key, age);
    _ = try ageEncrypt(&file_key, reader, age_writer.w);
    age_writer.deinit();
}

pub fn decrypt(
    allocator: Allocator,
    io: *Io,
    identities: []Key,
) !void {
    const reader = io.reader();
    const writer = io.writer();

    var age_reader = AgeReader(@TypeOf(reader)).init(allocator, reader);
    defer age_reader.deinit();

    var age = try age_reader.read();
    defer age.deinit(allocator);

    const file_key: Key = for (identities) |id| {
        break age.unwrap(allocator, id) catch |err| {
            std.debug.print("failed to unwrap: {any}\n", .{err});
            continue;
        };
    } else return error.NoIdentityMatch;
    defer file_key.deinit(allocator);

    if (!age.verify_hmac(allocator, &file_key)) {
        std.debug.print("hmac mismatch\n", .{});
    }

    _ = try ageDecrypt(&file_key, age_reader.r, writer);
}

test {
    _  = cli;
    _ = format;
    _ = bech32;
    _ = @import("recipient.zig");
    _ = @import("key.zig");
}
