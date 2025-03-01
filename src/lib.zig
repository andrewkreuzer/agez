const std = @import("std");
const Allocator = std.mem.Allocator;
const File = std.fs.File;

pub const bech32 = @import("bech32.zig");
pub const cli = @import("cli.zig");
const format = @import("format.zig");

pub const Io = @import("io.zig");
const armor = @import("armor.zig");
const ArmoredReader = armor.ArmoredReader;
const ArmoredWriter = armor.ArmoredWriter;
const Args = cli.Args;
const AgeFile = format.AgeFile;
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

pub fn encrypt(
    allocator: Allocator,
    io: *Io,
    args: Args
) !void {
    const reader = io.reader();
    const writer = io.writer();
    var armored_reader = ArmoredReader(@TypeOf(reader)){ .r = reader };
    const areader = armored_reader.reader();
    var armored_writer = ArmoredWriter(@TypeOf(writer)){ .w = writer };
    const awriter = armored_writer.writer();

    var is_armor = false;
    if (args.armor.flag()) {
        is_armor = true;
    }

    const file_key = try Key.initRandom(allocator, 16);

    var recipients = std.ArrayList(Recipient).init(allocator);
    if (args.passphrase.flag()) {
        var r = Recipient{ .type = .scrypt };
        var password_buf: [1024]u8 = undefined;
        const passphrase = try Io.read_password(&password_buf);
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

    var age = AgeFile(
        @TypeOf(reader),
        @TypeOf(writer),
        @TypeOf(areader),
        @TypeOf(awriter),
    ){
        .allocator = allocator,
        .r = reader,
        .w = writer,
        .ar = areader,
        .aw = awriter,
        .is_armored = is_armor,
        .version = .v1,
        .recipients = try recipients.toOwnedSlice(),
    };
    defer age.deinit();

    if (is_armor) {
        _ = try writer.write(armor.armor_begin_marker);
        _ = try writer.write("\n");
        try age.write(&file_key);
        _ = try file_key.ageEncrypt(reader, awriter);
        try armored_writer.flush();
        _ = try writer.write(armor.armor_end_marker);
        _ = try writer.write("\n");
    } else {
        try age.write(&file_key);
        _ = try file_key.ageEncrypt(reader, writer);
    }
}

pub fn decrypt(
    allocator: Allocator,
    io: *Io,
    args: Args
) !void {
    const reader = io.reader();
    const writer = io.writer();
    var armored_reader = ArmoredReader(@TypeOf(reader)){ .r = reader };
    const areader = armored_reader.reader();
    var armored_writer = ArmoredWriter(@TypeOf(writer)){ .w = writer };
    const awriter = armored_writer.writer();

    var is_armor = false;
    if (args.armor.flag()) {
        is_armor = true;
    }

    var age = AgeFile(
        @TypeOf(reader),
        @TypeOf(writer),
        @TypeOf(areader),
        @TypeOf(awriter),
    ){
        .allocator = allocator,
        .r = reader,
        .w = writer,
        .ar = areader,
        .aw = awriter,
        .is_armored = is_armor,
    };
    defer age.deinit();

    try age.read();

    var file_key: Key = undefined;
    if (age.recipients.?[0].type == .scrypt) {
        var password_buf = [_]u8{0} ** 128;
        const passphrase = try Io.read_password(&password_buf);
        defer std.crypto.utils.secureZero(u8, passphrase);
        file_key = try age.file_key(passphrase);
    } else {
        var identity_buf = [_]u8{0} ** 90;
        defer std.crypto.utils.secureZero(u8, &identity_buf);
        var identity: []u8 = undefined;
        if (args.identity.values()) |ids| {
            identity = try Io.identity(&identity_buf, ids);
        }
        file_key = try age.file_key(identity);
    }

    defer file_key.deinit(allocator);

    if (!age.verify_hmac(&file_key)) {
        std.debug.print("hmac mismatch\n", .{});
    }

    if (age.is_armored) {
        _ = try file_key.ageDecrypt(areader, writer);
    } else {
        _ = try file_key.ageDecrypt(reader, writer);
    }
}

test {
    _  = cli;
    _ = format;
    _ = bech32;
    _ = @import("recipient.zig");
    _ = @import("key.zig");
}
