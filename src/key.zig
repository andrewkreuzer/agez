const std = @import("std");
const assert = std.debug.assert;
const Allocator = @import("std").mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;

pub const Key = struct {
    const Self = @This();
    k: []u8,

    const nonce_length = 16;
    const chacha_tag_length = ChaCha20Poly1305.tag_length;
    const chacha_nonce_length = ChaCha20Poly1305.nonce_length;
    const chacha_key_length = ChaCha20Poly1305.key_length;

    /// Allocates a new FileKey with a copy of the key
    /// the caller must call deinit to free the memory securely
    pub fn init(allocator: Allocator, k: []const u8) !Key {
        return .{
            .k = try allocator.dupe(u8, k),
        };
    }

    /// Deallocates a FileKey ensuring the key
    /// is zeroed before freeing the memory
    pub fn deinit(self: *Self, allocator: Allocator) void {
        std.crypto.utils.secureZero(u8, self.k);
        allocator.free(self.k);
    }

    /// return a reference to the key
    pub fn key(self: *const Self) []const u8 {
        return self.k;
    }

    /// Encrypts the message (m) using ChaCha20Poly1305
    /// using age's encryption scheme and returns
    /// the nonce, ciphertext, and tag in out
    pub fn AgeEncrypt(
        self: *Self,
        allocator: Allocator,
        out: []u8,
        message: []const u8,
    ) !void {
        const total_size = nonce_length + message.len + chacha_tag_length;
        assert(out.len == total_size);
        assert(message.len <= 64 * (@as(u39, 1 << 32) - 1));

        // the key used to encrypt the payload
        // derived from the file key and the nonce
        var encryption_key: [32]u8 = undefined;
        std.crypto.utils.secureZero(u8, &encryption_key);

        // the nonce used to generate the encryption
        // key, randomly generated from /dev/random
        var key_nonce: [nonce_length]u8 = undefined;
        std.crypto.utils.secureZero(u8, &key_nonce);

        // the tag returned from ChaCha20Poly1305
        var tag: [chacha_tag_length]u8 = undefined;

        // additional data for ChaCha20Poly1305
        // age doesn't use this so we set it empty
        const ad = [_]u8{};

        // the nonce used to encrypt the payload, changes for each block,
        // starting at 0 and incrementing by 1 (big endian) for each block the
        // last byte is 0x01 for the last block and 0x00 for all other blocks
        var nonce = [_]u8{0x00} ** chacha_nonce_length;

        // the encrypted payload
        const ciphertext = try allocator.alloc(u8, message.len);
        defer allocator.free(ciphertext);

        // TODO: we'll assume no issues for now, GRND_RANDOM
        _ = std.os.linux.getrandom(&key_nonce, key_nonce.len, 0x0002);

        const k = hkdf.extract(&key_nonce, self.key());
        hkdf.expand(&encryption_key, "payload", k);

        nonce[nonce.len-1] = 0x01; // assume we're on the last block, TODO: don't

        ChaCha20Poly1305.encrypt(ciphertext, &tag, message, &ad, nonce, encryption_key);

        @memcpy(
            out[0..nonce_length],
            &key_nonce
        );
        @memcpy(
            out[nonce_length..nonce_length+message.len],
            ciphertext
        );
        @memcpy(out[nonce_length+message.len..], &tag);
    }

    /// Decrypts the payload using ChaCha20Poly1305
    /// and returns the plaintext in message
    pub fn AgeDecrypt(
        self: *Self,
        message: []u8,
        payload: []const u8,
    ) anyerror!void {
        assert(message.len == payload.len - nonce_length - chacha_tag_length);
        assert(payload.len == nonce_length + message.len + chacha_tag_length);

        // the key used to decrypt the payload
        // derived from the file key and the
        // randomly generated key nonce
        var encryption_key: [32]u8 = undefined;
        std.crypto.utils.secureZero(u8, &encryption_key);

        // the nonce used to generate the encryption key
        // always the first 16 bytes of the ciphertext
        var key_nonce: *const [nonce_length]u8 = undefined;

        // the ChaCha20Poly1305 tag used to authenticate the payload
        // always the last 16 bytes of the ciphertext
        var tag: [chacha_tag_length]u8 = undefined;

        // additional data for ChaCha20Poly1305
        // age doesn't use this so we set it empty
        const ad = [_]u8{};

        // the nonce used to encrypt the payload, changes for each block,
        // starting at 0 and incrementing by 1 (big endian) for each block the
        // last byte is 0x01 for the last block and 0x00 for all other blocks
        var nonce = [_]u8{0x00} ** 12;

        key_nonce = payload[0..nonce_length];
        const k = hkdf.extract(key_nonce, self.k);
        hkdf.expand(&encryption_key, "payload", k);

        const tag_start = payload.len - chacha_tag_length;
        @memcpy(&tag, payload[tag_start..]);

        const ciphertext = payload[key_nonce.len..tag_start];

        nonce[chacha_nonce_length-1] = 0x01; // assume we're on the last block TODO: don't

        try ChaCha20Poly1305.decrypt(message, ciphertext, tag, &ad, nonce, encryption_key);
    }
};

const KeyError = error{
    InvalidKey,
};

test "round trip" {
    const allocator = std.testing.allocator;
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
    };

    for (cases) |c| {
        var key = try Key.init(allocator, c.key);
        defer key.deinit(allocator);

        const ciphertext = try allocator.alloc(u8,
            Key.nonce_length + c.plaintext.len + Key.chacha_tag_length
        );
        const plaintext = try allocator.alloc(u8, c.plaintext.len);
        defer allocator.free(ciphertext);
        defer allocator.free(plaintext);

        _ = try key.AgeEncrypt(allocator, ciphertext, c.plaintext);
        _ = try key.AgeDecrypt(plaintext, ciphertext);

        try std.testing.expectEqualSlices(u8, plaintext, c.plaintext);
    }
}
