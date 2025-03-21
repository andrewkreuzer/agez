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

        var identities = [_]Key{
            try Key.init(allocator, testkit.identity),
        };
        defer identities[0].deinit(allocator);

        var fbs = io.fixedBufferStream(testkit.contents);
        const reader = fbs.reader().any();
        const writer = io.null_writer.any();
        lib.decrypt(allocator, reader, writer, &identities) catch |err| switch (err) {
            // expect: no match
            error.NoIdentityMatch
                => try t.expectEqualStrings(testkit.expect, "no match"),
            // expect: HMAC failure
            error.InvalidHmac
                => try t.expectEqualStrings(testkit.expect, "HMAC failure"),
            // expect: armor failure
            error.ArmorDecodeError,
            error.ArmorInvalidLineLength,
            error.ArmorNoEndMarker
                => try t.expectEqualStrings(testkit.expect, "armor failure"),
            // expect: header failure
            error.InvalidHeader,
            error.InvalidAscii,
            error.InvalidRecipientType,
            error.InvalidRecipientArgs,
            error.InvalidCharacter,
            error.InvalidScryptSalt,
            error.InvalidScryptBody,
            error.InvalidScryptKeyLength,
            error.InvalidScryptSaltLength,
            error.InvalidScryptWorkFactor,
            error.InvalidX25519KeyLength,
            error.InvalidX25519ShareLength,
            error.InvalidX25519Body,
            error.InvalidX25519Argument,
            error.IdentityElement
                => try t.expectEqualStrings(testkit.expect, "header failure"),
            // expect: payload failure
            error.InvalidKeyNonce,
            error.AgeDecryptFailure,
            error.WeakParameters
                => try t.expectEqualStrings(testkit.expect, "payload failure"),
            else => {
                std.debug.print("Error decrypting: {any}\n", .{err});
                try std.testing.expect(false);
            }
        };
    }
}
