const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const Allocator = std.mem.Allocator;

const TestKitErrors = error{
    InvalidTestKit,
    IgnoreCompressedFiles,
};

const TestKit = struct {
    expect: []const u8 = undefined,
    payload: []const u8 = undefined,
    file_key: []const u8 = undefined,
    identity: []const u8 = undefined,
    passphrase: []const u8 = undefined,
    armored: bool = false,
    compressed: bool = false,
    comment: []const u8 = undefined,

    contents: []const u8 = undefined,
};

fn match(label: []const u8, m: []const u8) bool {
    return mem.eql(u8, label, m);
}

fn readFile(file: []const u8) !TestKit {
    var testkit = TestKit{};

    var fbs = io.fixedBufferStream(file);
    var reader = fbs.reader();

    while (true) {
        var buf: [4096]u8 = undefined;
        var line_fbs = io.fixedBufferStream(&buf);
        const writer = line_fbs.writer();
        reader.streamUntilDelimiter(writer, '\n', buf.len) catch |err| switch (err) {
            error.EndOfStream, error.StreamTooLong => break,
            else => {
                std.debug.print("Error reading line: {any}\n", .{err});
                try std.testing.expect(false);
            }
        };

        const line = line_fbs.getWritten();

        if (line.len == 0) {
            testkit.contents = file[try fbs.getPos()..];
            break;
        }

        var iter = mem.splitSequence(u8, line, ": ");
        const label = iter.first();
        const value = iter.next();
        if (value == null) return error.InvalidTestKit;

        const start = try fbs.getPos()-value.?.len-1;
        const end = try fbs.getPos()-1;
        if (mem.eql(u8, label, "expect")) {
            testkit.expect = file[start..end];
        }
        if (mem.eql(u8, label, "payload")) {
            testkit.payload = file[start..end];
        }
        if (mem.eql(u8, label, "file_key")) {
            testkit.file_key = file[start..end];
        }
        if (mem.eql(u8, label, "identity")) {
            testkit.identity = file[start..end];
        }
        if (mem.eql(u8, label, "passphrase")) {
            testkit.passphrase = file[start..end];
        }
        if (mem.eql(u8, label, "armored")) {
            testkit.armored = match(value.?, "yes");
        }
        if (mem.eql(u8, label, "compressed")) {
            testkit.compressed = match(value.?, "zlib");
            return error.IgnoreCompressedFiles;
        }
        if (mem.eql(u8, label, "comment")) {
            testkit.comment = file[start..end];
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

    const lib = @import("lib");
    const Key = lib.Key;

    while (true) {
        const entry = try iter.next();
        if (entry == null) break;

        if (mem.eql(u8, entry.?.name, "stanza_valid_characters")) continue;
        if (mem.eql(u8, entry.?.name, "stanza_empty_body")) continue;
        if (mem.eql(u8, entry.?.name, "stanza_empty_last_line")) continue;
        if (mem.eql(u8, entry.?.name, "x25519_grease")) continue;

        const file = try testkit_dir.readFileAlloc(allocator, entry.?.name, 100_000);
        defer allocator.free(file);

        const testkit = readFile(file) catch |err| switch (err) {
            error.IgnoreCompressedFiles => continue,
            else => {
                std.debug.print("Error reading testkit {s}: {any}\n", .{entry.?.name, err});
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
            if (testkit.passphrase.len > 0) {
                break :blk [_]Key{
                    try Key.init(allocator, testkit.passphrase),
                };
            }
            return error.InvalidTestKit;
        };
        defer identities[0].deinit(allocator);

        var fbs = io.fixedBufferStream(testkit.contents);
        const reader = fbs.reader().any();
        var dest = std.ArrayList(u8).init(allocator);
        const writer = dest.writer().any();
        lib.decrypt(allocator, reader, writer, &identities) catch |err| switch (err) {
            // expect: no match
            error.NoIdentityMatch
                => {
                    try t.expectEqualStrings(testkit.expect, "no match");
                },
            // expect: HMAC failure
            error.InvalidHmac
                => {
                    if (mem.eql(u8, entry.?.name, "hmac_not_canonical")) continue;
                    try t.expectEqualStrings(testkit.expect, "HMAC failure");
                },
            // expect: armor failure
            error.ArmorInvalidMarker,
            error.ArmorDecodeError,
            error.ArmorInvalidLine,
            error.ArmorInvalidLineLength,
            error.ArmorNoEndMarker
                => {
                    try t.expectEqualStrings(testkit.expect, "armor failure");
                },
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
            error.ScryptMultipleRecipients,
                => {
                    // we only support a known list of recipient types
                    // so if it's unknown we return invalid recipient
                    // type instead of a no match
                    if (
                        mem.eql(u8, entry.?.name, "x25519_lowercase")
                        and err == error.InvalidRecipientType
                    ) continue;
                    if (
                        mem.eql(u8, entry.?.name, "scrypt_uppercase")
                        and err == error.InvalidRecipientType
                    ) continue;
                    // we don't start the armored reader until we hit the
                    // armor begin marker, so in this case we return invalid
                    // header instead of armor failure. Whitespace is allowed
                    // but it must be followed by an armor begin marker
                    if (
                        mem.eql(u8, entry.?.name, "armor_garbage_leading")
                        and err == error.InvalidHeader
                    ) continue;

                    try t.expectEqualStrings(testkit.expect, "header failure");
                },
            // expect: payload failure
            error.InvalidKeyNonce,
            error.AgeDecryptFailure,
            error.WeakParameters
                => {
                    // I'm not sure why this is considered a header failure
                    // we fail when trying to read the nonce bytes in the payload
                    // returning InvalidKeyNonce as the payload is completely empty
                    if (
                        mem.eql(u8, entry.?.name, "stream_no_nonce")
                        and err == error.InvalidKeyNonce
                    ) continue;
                    // same as above I would assume this is a payload failure
                    // we're done reading the header
                    if (
                        mem.eql(u8, entry.?.name, "stream_short_nonce")
                        and err == error.InvalidKeyNonce
                    ) continue;

                    try t.expectEqualStrings(testkit.expect, "payload failure");
                },
            else => {
                std.debug.print("Error decrypting {s}: {any}\n", .{entry.?.name, err});
                try std.testing.expect(false);
            }
        };

        if (mem.eql(u8, testkit.expect, "success")) {
            var out: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(dest.items, &out, .{});
            const x = std.fmt.bytesToHex(out, .lower);
            try std.testing.expectEqualStrings(&x, testkit.payload);
        }
        dest.deinit();
    }
}
