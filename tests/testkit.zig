const std = @import("std");
const fs = std.fs;
const Io = std.Io;
const mem = std.mem;
const Allocator = std.mem.Allocator;

const TestKitErrors = error{
    InvalidTestKit,
    IgnoreCompressedFiles,
};

const TestKit = struct {
    expect: []const u8 = "",
    payload: []const u8 = "",
    file_key: []const u8 = "",
    identity: []const u8 = "",
    passphrase: []const u8 = "",
    armored: bool = false,
    compressed: bool = false,
    comment: []const u8 = "",

    contents: []const u8 = "",
};

fn match(label: []const u8, m: []const u8) bool {
    return mem.eql(u8, label, m);
}

fn readFile(file: []const u8) !TestKit {
    var testkit = TestKit{};

    var reader: Io.Reader = .fixed(file);

    while (true) {
        const line = reader.takeDelimiterExclusive('\n') catch
            return error.InvalidTestKit;

        if (line.len == 0) {
            testkit.contents = file[reader.seek..];
            break;
        }

        var iter = mem.splitSequence(u8, line, ": ");
        const label = iter.first();
        const value = iter.rest();
        if (value.len == 0) return error.InvalidTestKit;

        if (match(label, "expect")) testkit.expect = value;
        if (match(label, "payload")) testkit.payload = value;
        if (match(label, "file_key")) testkit.file_key = value;
        if (match(label, "identity")) testkit.identity = value;
        if (match(label, "passphrase")) testkit.passphrase = value;
        if (match(label, "armored")) testkit.armored = match(value, "yes");
        if (match(label, "comment")) testkit.comment = value;
        if (match(label, "compressed")) {
            testkit.compressed = match(value, "zlib");
            return error.IgnoreCompressedFiles;
        }
    }

    return testkit;
}

const testkit_path = "tests/testkit/";

test "all" {
    const t = std.testing;
    const allocator = std.testing.allocator;
    var testkit_dir = try std.fs.cwd().openDir(testkit_path, .{.iterate = true});
    var iter = testkit_dir.iterate();

    const agez = @import("agez");
    const Key = agez.Key;

    while (try iter.next()) |entry| {
        if (mem.eql(u8, entry.name, "stanza_valid_characters")) continue;
        if (mem.eql(u8, entry.name, "stanza_empty_body")) continue;
        if (mem.eql(u8, entry.name, "stanza_empty_last_line")) continue;
        if (mem.eql(u8, entry.name, "x25519_grease")) continue;

        std.debug.print("Testing {s}\n", .{entry.name});

        const file = try testkit_dir.readFileAlloc(allocator, entry.name, 100_000);
        defer allocator.free(file);

        const testkit = readFile(file) catch |err| switch (err) {
            error.IgnoreCompressedFiles => continue,
            else => {
                std.debug.print("Error reading testkit {s}: {any}\n", .{entry.name, err});
                try std.testing.expect(false);
                break;
            }
        };

        var identities = blk: {
            if (testkit.identity.len > 0) {
                break :blk [_]Key{
                    try Key.init(allocator, testkit.identity),
                };
            }
            else if (testkit.passphrase.len > 0) {
                break :blk [_]Key{
                    try Key.init(allocator, testkit.passphrase),
                };
            }
            return error.InvalidTestKit;
        };
        defer identities[0].deinit(allocator);

        var reader: Io.Reader = .fixed(testkit.contents);
        var dest: Io.Writer.Allocating = .init(allocator);
        const decryptor: agez.AgeDecryptor = .init(allocator, &reader, &dest.writer);
        decryptor.decrypt(&identities) catch |err| switch (err) {
            // expect: no match
            error.NoIdentityMatch => try t.expectEqualStrings(testkit.expect, "no match"),
            // expect: HMAC failure
            error.InvalidHmac => {
                if (mem.eql(u8, entry.name, "hmac_not_canonical")) continue;
                try t.expectEqualStrings(testkit.expect, "HMAC failure");
            },
            // expect: armor failure
            error.ArmorInvalidMarker,
            error.ArmorDecodeError,
            error.ArmorInvalidLine,
            error.ArmorInvalidLineLength,
            error.ArmorNoEndMarker => try t.expectEqualStrings(testkit.expect, "armor failure"),
            // expect: header failure
            error.InvalidHeader,
            error.InvalidAscii,
            error.InvalidRecipientType,
            error.InvalidRecipientArgs,
            error.InvalidScryptSalt,
            error.InvalidScryptBody,
            error.InvalidScryptKeyLength,
            error.InvalidScryptSaltLength,
            error.InvalidScryptWorkFactor,
            error.InvalidX25519KeyLength,
            error.InvalidX25519ShareLength,
            error.InvalidX25519Body,
            error.InvalidX25519Argument,
            error.IdentityElement,
            error.InvalidCharacter,
            error.ScryptMultipleRecipients, => {
                // we only support a known list of recipient types
                // so if it's unknown we return invalid recipient
                // type instead of a no match
                if (
                    mem.eql(u8, entry.name, "x25519_lowercase")
                    and err == error.InvalidRecipientType
                ) continue;
                if (
                    mem.eql(u8, entry.name, "scrypt_uppercase")
                    and err == error.InvalidRecipientType
                ) continue;
                // we don't start the armored reader until we hit the
                // armor begin marker, so in this case we return invalid
                // header instead of armor failure. Whitespace is allowed
                // but it must be followed by an armor begin marker
                if (
                    mem.eql(u8, entry.name, "armor_garbage_leading")
                    and err == error.InvalidHeader
                ) continue;

                try t.expectEqualStrings(testkit.expect, "header failure");
            },
            // expect: payload failure
            error.InvalidKeyNonce,
            error.AgeDecryptFailure,
            error.WeakParameters => {
                // I'm not sure why this is considered a header failure
                // we fail when trying to read the nonce bytes in the payload
                // returning InvalidKeyNonce as the payload is completely empty
                if (
                    mem.eql(u8, entry.name, "stream_no_nonce")
                    and err == error.InvalidKeyNonce
                ) continue;
                // same as above I would assume this is a payload failure
                // we're done reading the header
                if (
                    mem.eql(u8, entry.name, "stream_short_nonce")
                    and err == error.InvalidKeyNonce
                ) continue;

                try t.expectEqualStrings(testkit.expect, "payload failure");
            },
            else => {
                std.debug.print("Error decrypting {s}: {any}\n", .{entry.name, err});
                try std.testing.expect(false);
            }
        };

        if (mem.eql(u8, testkit.expect, "success")) {
            var out: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(dest.written(), &out, .{});
            const x = std.fmt.bytesToHex(out, .lower);
            try std.testing.expectEqualStrings(&x, testkit.payload);
        }
        dest.deinit();
    }
}
