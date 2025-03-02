const std = @import("std");
const Allocator = std.mem.Allocator;
const File = std.fs.File;

const armor = @import("armor.zig");
pub const bech32 = @import("bech32.zig");
pub const cli = @import("cli.zig");
const format = @import("format.zig");
const Age = format.Age;
const AgeReader = format.AgeReader;
const AgeWriter = format.AgeWriter;
const Args = cli.Args;
pub const Io = @import("io.zig");
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

pub fn encrypt(
    allocator: Allocator,
    io: *Io,
    args: Args
) !void {
    const reader = io.reader();
    const writer = io.writer();

    const armored = args.armor.flag();
    const file_key = try Key.initRandom(allocator, 16);

    var recipients = std.ArrayList(Recipient).init(allocator);
    if (args.passphrase.flag()) {
        var r = Recipient{ .type = .scrypt };
        var passphrase_buf: [1024]u8 = undefined;
        const passphrase = try Io.read_passphrase(&passphrase_buf);
        defer std.crypto.utils.secureZero(u8, passphrase);
        try r.wrap(allocator, file_key, passphrase);
        try recipients.append(r);
    }

    if (args.identity.values()) |ids| if (ids.len > 0) {
        var r = Recipient{ .type = .X25519 };
        var identity_buf: [90]u8 = undefined;
        var recipient_buf: [90]u8 = undefined;
        var key: [32]u8 = undefined;
        var secret_key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &secret_key);

        const identity = try Io.identity(&identity_buf, ids);
        const decoded = try bech32.decode(&recipient_buf, "AGE-SECRET-KEY-", identity);
        _ = try bech32.convertBits(&secret_key, decoded.data, 5, 8, false);
        key = try std.crypto.dh.X25519.recoverPublicKey(secret_key);

        try r.wrap(allocator, file_key, &key);
        try recipients.append(r);
    };

    if (args.recipient.values()) |values| for (values) |recipient| {
        var r = Recipient{ .type = .X25519 };
        var recipient_buf: [90]u8 = undefined;
        var public_key: [32]u8 = undefined;

        const decoded = try bech32.decode(&recipient_buf, "age", recipient);
        _ = try bech32.convertBits(&public_key, decoded.data, 5, 8, false);

        try r.wrap(allocator, file_key, &public_key);
        try recipients.append(r);
    };

    const age: Age = .{
        .version = .v1,
        .recipients = recipients,
    };
    var header_writer = AgeWriter(@TypeOf(writer)).init(allocator, writer, armored);
    try header_writer.write(&file_key, age);
    _ = try file_key.ageEncrypt(reader, header_writer.w);
    header_writer.deinit();
}

pub fn decrypt(
    allocator: Allocator,
    io: *Io,
    args: Args
) !void {
    const reader = io.reader();
    const writer = io.writer();

    var age_reader = AgeReader(@TypeOf(reader)).init(allocator, reader);
    defer age_reader.deinit();

    var age = try age_reader.read();
    defer age.deinit(allocator);

    var file_key: Key = undefined;
    if (age.recipients.items[0].type == .scrypt) {
        var passphrase_buf = [_]u8{0} ** 128;
        const passphrase = try Io.read_passphrase(&passphrase_buf);
        defer std.crypto.utils.secureZero(u8, passphrase);
        file_key = try age.file_key(allocator, passphrase);
    } else {
        var identity_buf = [_]u8{0} ** 90;
        defer std.crypto.utils.secureZero(u8, &identity_buf);
        var identity: []u8 = undefined;
        if (args.identity.values()) |ids| {
            identity = try Io.identity(&identity_buf, ids);
        }
        file_key = try age.file_key(allocator, identity);
    }

    defer file_key.deinit(allocator);

    if (!age.verify_hmac(allocator, &file_key)) {
        std.debug.print("hmac mismatch\n", .{});
    }

    _ = try file_key.ageDecrypt(age_reader.r, writer);
}

test {
    _  = cli;
    _ = format;
    _ = bech32;
    _ = @import("recipient.zig");
    _ = @import("key.zig");
}
