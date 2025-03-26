const std = @import("std");
const Allocator = std.mem.Allocator;
const AnyReader = std.io.AnyReader;
const AnyWriter = std.io.AnyWriter;
const ArrayList = std.ArrayList;
const File = std.fs.File;

pub const bech32 = @import("bech32.zig");
pub const cli = @import("cli.zig");
pub const X25519 = @import("X25519.zig");
pub const ssh = @import("ssh/lib.zig");
pub const Io = @import("io.zig");
pub const Key = @import("key.zig").Key;
pub const Recipient = @import("recipient.zig").Recipient;

const armor = @import("armor.zig");
const format = @import("format.zig");
const _age = @import("age.zig");
const ageEncrypt = _age.ageEncrypt;
const ageDecrypt = _age.ageDecrypt;
const Age = _age.Age;
const AgeReader = format.AgeReader;
const AgeWriter = format.AgeWriter;
const Args = cli.Args;

pub fn encrypt(
    allocator: Allocator,
    reader: AnyReader,
    writer: AnyWriter,
    file_key: Key,
    recipients: ArrayList(Recipient),
    armored: bool,
) !void {
    const age: Age = .{ .version = .v1, .recipients = recipients, };
    var age_writer = AgeWriter(@TypeOf(writer)).init(allocator, writer, armored);
    defer age_writer.deinit();

    try age_writer.write(&file_key, age);

    _ = try ageEncrypt(&file_key, reader, age_writer.w);
}

pub fn decrypt(
    allocator: Allocator,
    reader: AnyReader,
    writer: AnyWriter,
    identities: []Key,
) !void {
    var age_reader = AgeReader(@TypeOf(reader)).init(allocator, reader);
    defer age_reader.deinit();

    var age = try age_reader.read();
    defer age.deinit(allocator);

    const file_key: Key = try age.unwrap(allocator, identities);
    defer file_key.deinit(allocator);

    try age.verify_hmac(&file_key);

    _ = try ageDecrypt(&file_key, age_reader.r, writer);
}

test {
    _  = _age;
    _  = cli;
    _ = format;
    _ = bech32;
    _ = armor;
    _ = @import("recipient.zig");
    _ = @import("key.zig");
    _ = @import("ssh/rsa.zig");
}
