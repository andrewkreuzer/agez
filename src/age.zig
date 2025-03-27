const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const generate_hmac = @import("format.zig").generate_hmac;
const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

pub const Header = struct {
    version: ?Version = null,
    recipients: ArrayList(Recipient),
    mac: ?[]u8 = null,
    bytes: ?[]u8 = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .recipients = ArrayList(Recipient).init(allocator),
        };
    }

    pub fn verify_hmac(self: *Self, fk: *const Key) !void {
        const encoded = generate_hmac(self.bytes.?, fk);
        if (!std.mem.eql(u8, self.mac.?, &encoded)) {
            return error.InvalidHmac;
        }
    }

    pub fn unwrap(self: *Self, allocator: Allocator, identities: []Key) !Key {
        for (self.recipients.items) |*r| {
            for (identities) |identity| {
                return r.unwrap(allocator, identity) catch |err| switch (err) {
                    error.IncompatibleKey,
                    error.AuthenticationFailed
                        => continue,
                    else => return err,
                };
            }
        }
        return error.NoIdentityMatch;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (self.recipients.items) |*r| {
            r.deinit(allocator);
        }
        self.recipients.deinit();
        if (self.mac) |mac| {
            allocator.free(mac);
        }
        if (self.bytes) |header| {
            allocator.free(header);
        }
        self.mac = null;
        self.bytes = null;
    }

};

/// The version of the age file.
pub const Version = enum {
    v1,
    none,

    pub const prefix = "age-encryption.org/";

    pub fn fromStr(str: []u8) Version {
        if (mem.eql(u8, str, prefix ++ "v1")) {
            return .v1;
        }
        return .none;
    }

    pub fn toString(self: Version) []const u8 {
        switch (self) {
            .v1 => return prefix ++ "v1",
            .none => return "",
        }
    }

    pub fn eql(self: Version, str: []u8) bool {
        return mem.eql(u8, str, @tagName(self));
    }
};


const nonce_length = 16;
const chacha_tag_length = ChaCha20Poly1305.tag_length;
const chacha_nonce_length = ChaCha20Poly1305.nonce_length;
const chacha_key_length = ChaCha20Poly1305.key_length;
const age_chunk_size = 64 * 1024;

/// Encrypts data from reader into writer with
/// age's ChaCha20Poly1305 encryption scheme
pub fn encrypt(key: *const Key, reader: anytype, writer: anytype) !void {
    var encryptor = try Encryptor(@TypeOf(writer)).init(key, writer);
    try encryptor.encrypt(reader);
}

pub fn Encryptor(WriterType: type) type {
    return struct {
        const Self = @This();

        key: *const Key,
        nonce: [nonce_length]u8 = undefined,
        writer: WriterType,

        read_buffer: [age_chunk_size]u8 = undefined,
        write_buffer: [age_chunk_size + chacha_tag_length]u8 = undefined,

        pub fn init(key: *const Key, writer: WriterType) !Self {
            var self = Self{ .key = key, .writer = writer };
            _ = try writer.write(&self.generateKeyNonce());
            return self;
        }

        pub fn encrypt(self: *Self, reader: anytype) !void {
            // the tag returned from ChaCha20Poly1305
            var tag: [chacha_tag_length]u8 = undefined;
            defer crypto.utils.secureZero(u8, &tag);

            // additional data for ChaCha20Poly1305
            // age doesn't use this so we set it empty
            const ad = [_]u8{};

            // the nonce used to encrypt the payload, changes for each block,
            // starting at 0 and incrementing by 1 (big endian) for each block. The
            // last byte is 0x01 for the last block and 0x00 for all other blocks
            var nonce = [_]u8{0x00} ** chacha_nonce_length;

            // the key used to encrypt the payload
            // derived from the file key and the nonce
            var encryption_key: [ChaCha20Poly1305.key_length]u8 = undefined;
            crypto.utils.secureZero(u8, &encryption_key);

            const k = hkdf.extract(&self.nonce, self.key.key().bytes);
            hkdf.expand(&encryption_key, "payload", k);

            while (true) {
                const read = try reader.read(&self.read_buffer);
                if (read == 0) break;
                if (read < self.read_buffer.len) {
                    nonce[nonce.len-1] = 0x01;
                }

                ChaCha20Poly1305.encrypt(
                    self.write_buffer[0..read],
                    &tag,
                    self.read_buffer[0..read],
                    &ad,
                    nonce,
                    encryption_key
                );

                _ = try self.writer.write(self.write_buffer[0..read]);
                _ = try self.writer.write(&tag);
                try incrementNonce(&nonce);
            }
        }

        // the nonce used to generate the encryption key
        // filled with random bytes
        fn generateKeyNonce(self: *Self) [nonce_length]u8 {
            crypto.random.bytes(&self.nonce);
            return self.nonce;
        }
    };
}

/// Decrypts the data from reader into writer
/// using age's ChaCha20Poly1305 encryption scheme
pub fn decrypt(key: *const Key, reader: anytype, writer: anytype,) !void {
    var decryptor = try Decryptor(@TypeOf(reader)).init(key, reader);
    try decryptor.decrypt(writer);
}

pub fn Decryptor(ReaderType: type) type {
    return struct {
        const Self = @This();

        key: *const Key,
        nonce: [nonce_length]u8 = undefined,
        reader: ReaderType,

        read_buffer: [age_chunk_size + chacha_tag_length]u8 = undefined,
        write_buffer: [age_chunk_size]u8 = undefined,

        pub fn init(key: *const Key, reader: ReaderType) !Self {
            var self = Self{ .key = key, .reader = reader };
            try self.readKeyNonce();
            return self;
        }

        pub fn decrypt(self: *Self, writer: anytype) !void {
            // the ChaCha20Poly1305 tag used to authenticate the payload
            // always the last 16 bytes of the ciphertext
            var tag: [chacha_tag_length]u8 = undefined;
            crypto.utils.secureZero(u8, &tag);

            // additional data for ChaCha20Poly1305
            // age doesn't use this so we set it empty
            const ad = [_]u8{};

            // the nonce used to encrypt the payload, changes for each block,
            // starting at 0 and incrementing by 1 (big endian) for each block. The
            // last byte is 0x01 for the last block and 0x00 for all other blocks
            var nonce = [_]u8{0x00} ** 12;

            // the key used to encrypt the payload
            // derived from the file key and the nonce
            var encryption_key: [32]u8 = undefined;
            crypto.utils.secureZero(u8, &encryption_key);

            const k = hkdf.extract(&self.nonce, self.key.slice.k);
            hkdf.expand(&encryption_key, "payload", k);

            while (true) {
                const read = try self.reader.readAll(&self.read_buffer);
                if (read == 0) break;
                if (read < chacha_tag_length) return error.AgeDecryptFailure;
                if (read < age_chunk_size) {
                    nonce[nonce.len-1] = 0x01;
                }

                @memcpy(&tag, self.read_buffer[read-chacha_tag_length..read]);

                ChaCha20Poly1305.decrypt(
                    self.write_buffer[0..read-chacha_tag_length],
                    self.read_buffer[0..read-chacha_tag_length],
                    tag,
                    &ad,
                    nonce,
                    encryption_key
                ) catch |err| switch (err) {
                    error.AuthenticationFailed => return error.AgeDecryptFailure,
                    else => return err,
                };
                _ = try writer.write(self.write_buffer[0..read-chacha_tag_length]);
                try incrementNonce(&nonce);
            }
        }

        fn readKeyNonce(self: *Self) !void {
            const n = try self.reader.readAll(&self.nonce);
            if (n != nonce_length) return error.InvalidKeyNonce;
        }
    };
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

const AgeError = error{
    AgeDecryptFailure,
    AuthenticationFailed,
    InvalidKeyNonce,
    InvalidHmac,
    NonceRollOver,
    NoIdentityMatch,
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
            .slice = .{ .k = try allocator.dupe(u8, c.key) }
        };
        defer key.deinit(allocator);

        var plaintext_fbs = std.io.fixedBufferStream(c.plaintext);
        const overhead = @divTrunc(c.plaintext.len, age_chunk_size) + 1;

        const ciphertext = try allocator.alloc(u8,
            nonce_length + c.plaintext.len + (chacha_tag_length * overhead)
        );
        var ciphertext_fbs = std.io.fixedBufferStream(ciphertext);
        defer allocator.free(ciphertext);

        const out = try allocator.alloc(u8, c.plaintext.len);
        var out_fbs = std.io.fixedBufferStream(out);
        defer allocator.free(out);

        _ = try encrypt(&key, plaintext_fbs.reader(), ciphertext_fbs.writer());

        ciphertext_fbs.reset();

        _ = try decrypt(&key, ciphertext_fbs.reader(), out_fbs.writer());

        try std.testing.expectEqualSlices(u8, out, c.plaintext);
    }
}
