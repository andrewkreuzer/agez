const std = @import("std");
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;

const Key = @import("key.zig").Key;
const Recipient = @import("recipient.zig").Recipient;

pub const stanza_arg = "ssh-ed25519";
const key_label = "age-encryption.org/v1/ssh-ed25519";

pub fn toStanza(allocator: Allocator, args: [][]u8, body: []u8) ![]const u8 {
    var buf: [109]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try std.fmt.format(
        writer,
        \\-> ssh-ed25519 {s} {s}
        \\{s}
        ,.{args[0], args[1], body}
    );

    return try allocator.dupe(u8, &buf);
}

pub fn fromPublicKey(allocator: Allocator, pk: []const u8, file_key: Key) !Recipient {
    var r = Recipient{ .type = .@"ssh-ed25519" };
    try r.wrap(allocator, file_key, pk);
    return r;
}


/// Decrypts the recipients body and returns the file key
pub fn unwrap(allocator: Allocator, identity: []const u8, args: [][]u8, body: []u8) !Key {
    // derived from the shared secret and salt
    // decrypts the file key from the recipients body
    var key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key);

    // the shortened fingerprint of the recipients public key
    var rpk_ssh_tag: [4]u8 = undefined;

    // the recipients ssh public key
    var epk: [32]u8 = undefined;

    // the encrypted file key
    var file_key_enc: [32]u8 = undefined;

    // the identities public key formatted for ssh
    var pk_ssh: [51]u8 = undefined;

    // the sha256 digest of the ssh public key
    var pk_ssh_tag: [Sha256.digest_length]u8 = undefined;

    // derived from the recipients ephemeral share
    // and the recipients public key
    var salt: [64]u8 = undefined;

    // derived from the last 16 bytes
    // of the recipients body, the Poly
    var tag: [16]u8 = undefined;

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    if (args.len != 2) {
        return error.InvalidRecipientArgs;
    }

    const Decoder = std.base64.standard_no_pad.Decoder;
    Decoder.decode(&rpk_ssh_tag, args[1]) catch {
        return error.InvalidSSHArgument;
    };
    Decoder.decode(&epk, args[0]) catch {
        return error.InvalidSSHArgument;
    };
    Decoder.decode(&file_key_enc, body) catch {
        return error.InvalidSSHBody;
    };

    const pk = identity[32..64];
    try ed25519SshFormat(&pk_ssh, pk);
    Sha256.hash(&pk_ssh, &pk_ssh_tag, .{});
    if (!mem.eql(u8, &rpk_ssh_tag, pk_ssh_tag[0..4])) {
        return error.InvalidSSHFingerprint;
    }

    var rk_hash: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(identity[0..32], &rk_hash, .{});
    const rk: [32]u8 = rk_hash[0..32].*;
    defer std.crypto.utils.secureZero(u8, &rk_hash);

    const rpk = try X25519.recoverPublicKey(rk);

    var shared_secret = blk: {
        var tweak: [32]u8 = undefined;
        hkdf.expand(
            &tweak,
            key_label,
            hkdf.extract(&pk_ssh, &[_]u8{})
        );
        break :blk try X25519.scalarmult(
           tweak,
           try X25519.scalarmult(rk, epk)
        );
    };
    defer std.crypto.utils.secureZero(u8, &shared_secret);

    @memcpy(salt[0..32], &epk);
    @memcpy(salt[32..], &rpk);

    const k = hkdf.extract(&salt, &shared_secret);
    hkdf.expand(&key, key_label, k);

    const tag_start = file_key_enc.len - ChaCha20Poly1305.tag_length;
    @memcpy(&tag, file_key_enc[tag_start..]);

    const payload = file_key_enc[0..tag_start];
    const file_key: Key = .{
        .k = try allocator.alloc(u8, payload.len),
    };

    try ChaCha20Poly1305.decrypt(file_key.k, payload, tag, &ad, nonce, key);

    return file_key;
}

/// Encrypts the file key in the recipients body
/// and populates the recipients type, args, and body
/// caller is responsible for deinit on the reciepient
pub fn wrap(allocator: Allocator, file_key: Key, public_key: []const u8) !Recipient {
    // derived from the shared secret and salt
    // encrypts the file key in the recipients body
    var key: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &key);

    // a randomly generated ephemeral secret
    // currently only supported on linux
    // as it's pulled from /dev/random
    var ephemeral_secret: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &ephemeral_secret);

    // the encrypted file key and tag to be base64
    // encoded and written to the reciepient's body
    var file_key_enc: [32]u8 = undefined;

    // the public key formatted for ssh
    var pk_ssh: [51]u8 = undefined;

    // base64 encoded public key
    // to be written to the reciepient
    var epk_b64: [43]u8 = undefined;

    // the sha256 digest of the ssh public key
    var pk_tag: [Sha256.digest_length]u8 = undefined;

    // the sha256 digest of the ssh public key
    var ssh_tag_b64: [6]u8 = undefined;

    // derived from the ephemeral share
    // and the recipients public key
    var salt: [64]u8 = undefined;

    // a blank nonce
    const nonce = [_]u8{0x00} ** 12;

    // an empty associated data
    const ad = [_]u8{};

    // tag returned from ChaCha20Poly1305
    var tag: [16]u8 = undefined;

    // the encrypted file key base64 encoded
    var body: [43]u8 = undefined;

    _ = std.os.linux.getrandom(
        &ephemeral_secret,
        ephemeral_secret.len,
        0x0002 // GRND_RANDOM
    );

    const epk = try X25519.recoverPublicKey(ephemeral_secret);
    const rpk = blk: {
        const rpk_ed = try std.crypto.ecc.Edwards25519.fromBytes(public_key[0..32].*);
        const rpk_x = try X25519.Curve.fromEdwards25519(rpk_ed);
        break :blk rpk_x.toBytes();
    };

    try ed25519SshFormat(&pk_ssh, public_key);
    Sha256.hash(&pk_ssh, &pk_tag, .{});

    var shared_secret = blk: {
        var tweak: [32]u8 = undefined;
        hkdf.expand(
            &tweak,
            key_label,
            hkdf.extract(&pk_ssh, &[_]u8{})
        );
        break :blk try X25519.scalarmult(
           tweak,
           try X25519.scalarmult(ephemeral_secret, rpk)
        );
    };
    defer std.crypto.utils.secureZero(u8, &shared_secret);

    @memcpy(salt[0..32], &epk);
    @memcpy(salt[32..], &rpk);

    const k = hkdf.extract(&salt, &shared_secret);
    hkdf.expand(&key, key_label, k);

    ChaCha20Poly1305.encrypt(file_key_enc[0..16], &tag, file_key.key(), &ad, nonce, key);

    @memcpy(file_key_enc[16..], &tag);

    const Encoder = std.base64.standard_no_pad.Encoder;
    _ = Encoder.encode(&body, &file_key_enc);
    _ = Encoder.encode(&ssh_tag_b64, pk_tag[0..4]);
    _ = Encoder.encode(&epk_b64, &epk);

    var args = try allocator.alloc([]u8, 2);
    args[0] = try allocator.dupe(u8, &ssh_tag_b64);
    args[1] = try allocator.dupe(u8, &epk_b64);

    return .{
        .type = .@"ssh-ed25519",
        .args = args,
        .body = try allocator.dupe(u8, &body),
    };
}

const SSHErrors = error{
    InvalidSSHKey,
    InvalidSSHFingerprint,
    InvalidSSHIdentity,
    InvalidSSHArgument,
    InvalidSSHBody,
    InvalidKeyCount,
};

const EncryptedPrivateKeySpec = struct {
    ciphername: []u8,
    kdfname: []u8,
    kdf: ?[]u8,
    keys: u32,
    public_key: []u8,
    private_key: []u8,
};

const SshPrivateKeySpec = struct {
    check1: u32,
    check2: u32,
    key_type: []u8,
    rest_key_data: []u8,
};

const SshEd25519PrivateKey = struct {
    public_key: []u8,
    private_key: []u8,
    comment: []u8,
    rest_padding: []u8,
};

const SshKeyTypes = union(enum) {
    ed25519: Ed25519.KeyPair,
    unsupported,
};

pub fn parseOpenSSHPrivateKey(data: []u8) !SshKeyTypes {
    var out_buf: [PemDecoder.max_key_size]u8 = undefined;
    const d = try PemDecoder.decode(&out_buf, data);

    const privat_key_auth_magic = "openssh-key-v1\x00";
    if (!mem.eql(u8, d[0..privat_key_auth_magic.len], privat_key_auth_magic)) {
        return error.InvalidSSHIdentity;
    }

    const remainder = d[privat_key_auth_magic.len..];
    const enc_pk = try parseIntoStruct(EncryptedPrivateKeySpec, remainder);
    if (enc_pk.keys != 1) {
        return error.InvalidKeyCount;
    }

    // TODO: decrypt the private key if needed

    const pk1 = try parseIntoStruct(SshPrivateKeySpec, enc_pk.private_key);
    if (pk1.check1 != pk1.check2) {
        return error.InvalidSSHKey;
    }

    if (mem.eql(u8, pk1.key_type, "ssh-ed25519")) {
        const k = try parseIntoStruct(SshEd25519PrivateKey, pk1.rest_key_data);
        const secret_key = try Ed25519.SecretKey.fromBytes(k.private_key[0..64].*);
        const key_pair = try Ed25519.KeyPair.fromSecretKey(secret_key);
        return .{ .ed25519 = key_pair };
    }

    return .unsupported;
}

fn parseIntoStruct(T: type, data: []u8) !T {
    var d = data;
    var out: T = undefined;
    const fields = @typeInfo(T).@"struct".fields;
    inline for (fields) |field| {
        switch (field.type) {
            u32 => {
                const size = @sizeOf(u32);
                @field(out, field.name) = mem.readInt(u32, d[0..size], .big);
                d = d[size..];
            },
            []u8 => {
                if (mem.eql(u8, field.name[0..4], "rest")) {
                    @field(out, field.name) = d[0..];
                    d = d[d.len..];
                } else {
                    const size: u32 = mem.readInt(u32, d[0..@sizeOf(u32)], .big);
                    d = d[@sizeOf(u32)..];
                    @field(out, field.name) = d[0..size];
                    d = d[size..];
                }
            },
            ?[]u8 => {
                const size: u32 = mem.readInt(u32, d[0..@sizeOf(u32)], .big);
                d = d[@sizeOf(u32)..];
                if (size == 0) {
                    @field(out, field.name) = null;
                } else {
                    @field(out, field.name) = d[0..size];
                    d = d[size..];
                }
            },
            else => unreachable,
        }
    }
    return out;
}

pub const PemDecoder = struct {
    pub const header = "-----BEGIN";
    pub const footer = "-----END";
    pub const max_key_size: usize = 1 << 14; // 16KiB
    pub const max_openssh_line_length: usize = 70 + 1; // 70 bytes + newline

    const Type = enum {
        rsaPublicKey,
        rsaPrivateKey,
        ed25519PublicKey,
        ed25519PrivateKey,
    };

    pub fn decode(dest: []u8, source: []const u8) ![]u8 {
        var source_fbs = std.io.fixedBufferStream(source);
        var reader = source_fbs.reader();
        var buf: [max_key_size]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        var writer = fbs.writer();
        var line_buf: [max_openssh_line_length]u8 = undefined;
        while (true) {
            var line_fbs = std.io.fixedBufferStream(&line_buf);
            const line_writer = line_fbs.writer();
            reader.streamUntilDelimiter(line_writer, '\n', line_buf.len) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            const line = line_fbs.getWritten();
            if (line.len == 0) break;
            if (mem.eql(u8, line[0..header.len], header)) {
                //TODO: parse header for keytype
                continue;
            }
            if (mem.eql(u8, line[0..footer.len], footer)) {
                continue;
            }
            _ = try writer.write(line);
        }
        const bytes = fbs.getWritten();
        const Decoder = std.base64.standard.Decoder;
        const size = try Decoder.calcSizeForSlice(bytes);
        Decoder.decode(dest[0..size], bytes) catch {
            return error.InvalidSSHIdentity;
        };
        return dest[0..size];
    }
};


fn ed25519SshFormat(out: []u8, key: []const u8) !void {
    var fbs = std.io.fixedBufferStream(out);
    const writer = fbs.writer();
    _ = try writer.write(&[_]u8{0x00, 0x00, 0x00, 0x0b});
    _ = try writer.write("ssh-ed25519");
    _ = try writer.write(&[_]u8{0x00, 0x00, 0x00, 0x20});
    _ = try writer.write(key);
}
