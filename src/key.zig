const std = @import("std");
const assert = std.debug.assert;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Allocator = @import("std").mem.Allocator;

pub const Key = struct {
    const Self = @This();
    k: []u8,

    const nonce_length = 16;
    const chacha_tag_length = ChaCha20Poly1305.tag_length;
    const chacha_nonce_length = ChaCha20Poly1305.nonce_length;
    const chacha_key_length = ChaCha20Poly1305.key_length;
    const age_chunk_size = 64 * 1024;

    /// Allocates a new Key with a copy of the key
    /// the caller must call deinit to free the memory securely
    pub fn init(allocator: Allocator, k: []const u8) !Key {
        return .{
            .k = try allocator.dupe(u8, k),
        };
    }

    /// Allocates a new Key with the provided len
    /// the caller must call deinit to free the memory securely
    pub fn initRandom(allocator: Allocator, len: usize) !Key {
        const k: Key = .{ .k = try allocator.alloc(u8, len) };
        _ = std.os.linux.getrandom(k.k.ptr, len, 0x0002);
        return k;
    }

    /// Deallocates a Key ensuring the key
    /// is zeroed before freeing the memory
    pub fn deinit(self: *const Self, allocator: Allocator) void {
        std.crypto.utils.secureZero(u8, self.k);
        allocator.free(self.k);
    }

    /// return a reference to the key
    pub fn key(self: *const Self) []const u8 {
        return self.k;
    }

    /// return the public key
    pub fn public(self: *const Self) ![32]u8 {
        const k: [32]u8 = self.k[0..chacha_key_length].*;
        return try std.crypto.dh.X25519.recoverPublicKey(k);
    }

    /// Encrypts the message using ChaCha20Poly1305
    /// using age's encryption scheme and returns
    /// the nonce, ciphertext, and tag in payload
    pub fn ageEncrypt(
        self: *const Self,
        reader: anytype,
        writer: anytype,
    ) !void {
        comptime {
            if (!@hasDecl(@TypeOf(reader), "read")) {
                @compileError("AgeEncrypt message must implement read");
            }
            if (!@hasDecl(@TypeOf(writer), "write")) {
                @compileError("AgeEncrypt payload must implement read");
            }
        }

        // the key used to encrypt the payload
        // derived from the file key and the nonce
        var encryption_key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &encryption_key);

        // the nonce used to generate the encryption
        // key, randomly generated from /dev/random
        var key_nonce: [nonce_length]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &key_nonce);

        // the tag returned from ChaCha20Poly1305
        var tag: [chacha_tag_length]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &key_nonce);

        // additional data for ChaCha20Poly1305
        // age doesn't use this so we set it empty
        const ad = [_]u8{};

        // the nonce used to encrypt the payload, changes for each block,
        // starting at 0 and incrementing by 1 (big endian) for each block. The
        // last byte is 0x01 for the last block and 0x00 for all other blocks
        var nonce = [_]u8{0x00} ** chacha_nonce_length;

        var read_buffer = [_]u8{0} ** age_chunk_size;
        var write_buffer = [_]u8{0} ** (age_chunk_size + chacha_tag_length);

        // TODO: we'll assume no issues for now, GRND_RANDOM
        _ = std.os.linux.getrandom(&key_nonce, key_nonce.len, 0x0002);

        const k = hkdf.extract(&key_nonce, self.key());
        hkdf.expand(&encryption_key, "payload", k);

        _ = try writer.write(&key_nonce);

        while (true) {
            const read = try reader.read(&read_buffer);
            if (read == 0) { break; }
            if (read < read_buffer.len) {
                nonce[nonce.len-1] = 0x01;
            }

            ChaCha20Poly1305.encrypt(
                write_buffer[0..read],
                &tag,
                read_buffer[0..read],
                &ad,
                nonce,
                encryption_key
            );

            _ = try writer.write(write_buffer[0..read]);
            _ = try writer.write(&tag);
            try incrementNonce(&nonce);
        }
    }

    /// Decrypts the payload using ChaCha20Poly1305
    /// and returns the plaintext in message
    pub fn ageDecrypt(
        self: *const Self,
        reader: anytype,
        writer: anytype,
    ) anyerror!void {
        comptime {
            if (!@hasDecl(@TypeOf(reader), "read")) {
                @compileError("AgeDecrypt payload must implement read");
            }
            if (!@hasDecl(@TypeOf(writer), "write")) {
                @compileError("AgeDecrypt message must implement write");
            }
        }

        // the key used to decrypt the payload
        // derived from the file key and the
        // randomly generated key nonce
        var encryption_key: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &encryption_key);

        // the nonce used to generate the encryption key
        // always the first 16 bytes of the ciphertext
        var key_nonce: [nonce_length]u8 = undefined;

        // the ChaCha20Poly1305 tag used to authenticate the payload
        // always the last 16 bytes of the ciphertext
        var tag: [chacha_tag_length]u8 = undefined;

        // additional data for ChaCha20Poly1305
        // age doesn't use this so we set it empty
        const ad = [_]u8{};

        // the nonce used to encrypt the payload, changes for each block,
        // starting at 0 and incrementing by 1 (big endian) for each block. The
        // last byte is 0x01 for the last block and 0x00 for all other blocks
        var nonce = [_]u8{0x00} ** 12;

        var read_buffer = [_]u8{0} ** (age_chunk_size + chacha_tag_length);
        var write_buffer = [_]u8{0} ** age_chunk_size;

        const key_nonce_read = try reader.readAll(&key_nonce);
        if (key_nonce_read != nonce_length) { return error.InvalidKeyNonce; }

        const k = hkdf.extract(&key_nonce, self.k);
        hkdf.expand(&encryption_key, "payload", k);

        while (true) {
            const read = try reader.readAll(&read_buffer);
            if (read == 0) { break; }
            if (read < age_chunk_size) {
                nonce[nonce.len-1] = 0x01;
            }

            @memcpy(&tag, read_buffer[read-chacha_tag_length..read]);

            try ChaCha20Poly1305.decrypt(
                write_buffer[0..read-chacha_tag_length],
                read_buffer[0..read-chacha_tag_length],
                tag,
                &ad,
                nonce,
                encryption_key
            );
            _ = try writer.write(write_buffer[0..read-chacha_tag_length]);
            try incrementNonce(&nonce);
        }
    }

    fn incrementNonce(nonce: []u8) !void {
        var i = nonce.len - 2;
        while (i >= 0) {
            nonce[i] +%= 1;

            if (nonce[i] != 0) { break; }
            else if (i == 0) {
                return error.NonceRollOver;
            }

            i -= 1;
        }
    }
};

const KeyError = error{
    InvalidKey,
    InvalidKeyNonce,
    NonceRollOver,
};

test "round trip" {
    const allocator = std.testing.allocator;
    const large_chunk = (64 * 1024) + 1;
    const cases = [_]struct {
        key: []const u8,
        plaintext: []const u8,
    }{
        .{ .key = "this is a key", .plaintext = "tests" },
        .{ .key = "this is a key", .plaintext = "this is a test" },
        .{ .key = "this is a key", .plaintext =
            \\"Lorem ipsum dolor sit amet, consectetur adipiscing elit,
            \\sed do eiusmod tempor incididunt ut labore et dolore magna
            \\aliqua. Ut enim ad minim veniam, quis nostrud exercitation
            \\ullamco laboris nisi ut aliquip ex ea commodo consequat.
            \\Duis aute irure dolor in reprehenderit in voluptate velit esse
            \\cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat
            \\cupidatat non proident, sunt in culpa qui officia deserunt mollit
            \\anim id est laborum."
        },
        .{ .key =
            \\"Lorem ipsum dolor sit amet, consectetur adipiscing elit,
            \\sed do eiusmod tempor incididunt ut labore et dolore magna
            \\aliqua. Ut enim ad minim veniam, quis nostrud exercitation
            \\ullamco laboris nisi ut aliquip ex ea commodo consequat.
            \\Duis aute irure dolor in reprehenderit in voluptate velit esse
            \\cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat
            \\cupidatat non proident, sunt in culpa qui officia deserunt mollit
            \\anim id est laborum."
            ,
            .plaintext = "this is a test",
        },
        .{ .key = "this is a key", .plaintext = "t" ** large_chunk },
    };

    for (cases) |c| {
        var key: Key = .{
            .k = try allocator.dupe(u8, c.key),
        };
        defer key.deinit(allocator);

        var plaintext_fbs = std.io.fixedBufferStream(c.plaintext);
        const overhead = @divTrunc(c.plaintext.len, Key.age_chunk_size) + 1;

        const ciphertext = try allocator.alloc(u8,
            Key.nonce_length + c.plaintext.len + (Key.chacha_tag_length * overhead)
        );
        var ciphertext_fbs = std.io.fixedBufferStream(ciphertext);
        defer allocator.free(ciphertext);

        const out = try allocator.alloc(u8, c.plaintext.len);
        var out_fbs = std.io.fixedBufferStream(out);
        defer allocator.free(out);

        _ = try key.ageEncrypt(plaintext_fbs.reader(), ciphertext_fbs.writer());

        ciphertext_fbs.reset();

        _ = try key.ageDecrypt(ciphertext_fbs.reader(), out_fbs.writer());

        try std.testing.expectEqualSlices(u8, out, c.plaintext);
    }
}
