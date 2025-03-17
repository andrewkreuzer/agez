const std = @import("std");
const mem = std.mem;
const Ed25519 = std.crypto.sign.Ed25519;

const Key = @import("../key.zig").Key;
const Rsa = @import("rsa.zig");
const PemDecoder = @import("lib.zig").PemDecoder;

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

const SshRsaPrivateKey = struct {
    n: []u8,
    e: []u8,
    d: []u8,
    iqmp: []u8,
    p: []u8,
    q: []u8,
    comment: []u8,
    rest_padding: []u8,
};

const SshEd25519PrivateKey = struct {
    public_key: []u8,
    private_key: []u8,
    comment: []u8,
    rest_padding: []u8,
};

pub fn parseOpenSshPrivateKey(data: []u8) !Key {
    var Decoder = PemDecoder{};
    var out_buf: [PemDecoder.max_key_size]u8 = undefined;
    const d = try Decoder.decode(&out_buf, data);

    const privat_key_auth_magic = "openssh-key-v1\x00";
    if (!mem.eql(u8, d[0..privat_key_auth_magic.len], privat_key_auth_magic)) {
        return error.InvalidSshKey;
    }

    const remainder = d[privat_key_auth_magic.len..];
    const enc_pk = try parseIntoStruct(EncryptedPrivateKeySpec, remainder);
    if (enc_pk.keys != 1) {
        // only one key is supported same as openSSH
        return error.InvalidKeyCount;
    }

    // TODO: decrypt the private key if needed

    const pk1 = try parseIntoStruct(SshPrivateKeySpec, enc_pk.private_key);
    if (pk1.check1 != pk1.check2) {
        return error.InvalidSshKey;
    }

    if (mem.eql(u8, pk1.key_type, "ssh-ed25519")) {
        const k = try parseIntoStruct(SshEd25519PrivateKey, pk1.rest_key_data);
        const secret_key = try Ed25519.SecretKey.fromBytes(k.private_key[0..64].*);
        const key_pair = try Ed25519.KeyPair.fromSecretKey(secret_key);
        return .{ .ed25519 = key_pair };
    } else if (mem.eql(u8, pk1.key_type, "ssh-rsa")) {
        const k = try parseIntoStruct(SshRsaPrivateKey, pk1.rest_key_data);
        var secret_key = try Rsa.SecretKey.fromParts(k.n, k.e, k.d, k.p, k.q);
        if (!try secret_key.validate()) return error.InvalidSshKey;
        try secret_key.precompute();
        const key_pair = try Rsa.KeyPair.fromPrivateKey(secret_key);
        return .{ .rsa = key_pair };
    }else {
        return error.UnsupportedSshKey;
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
                if (field.name.len > 3 and mem.eql(u8, field.name[0..4], "rest")) {
                    @field(out, field.name) = d[0..];
                    d = d[d.len..];
                } else {
                    const size: u32 = mem.readInt(u32, d[0..4], .big);
                    d = d[4..];
                    @field(out, field.name) = d[0..size];
                    d = d[size..];
                }
            },
            ?[]u8 => {
                const size: u32 = mem.readInt(u32, d[0..4], .big);
                d = d[4..];
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


pub fn ed25519SshFormat(out: []u8, key: []const u8) !void {
    var fbs = std.io.fixedBufferStream(out);
    const writer = fbs.writer();
    _ = try writer.write(&[_]u8{0x00, 0x00, 0x00, 0x0b});
    _ = try writer.write("ssh-ed25519");
    _ = try writer.write(&[_]u8{0x00, 0x00, 0x00, 0x20});
    _ = try writer.write(key);
}

const OpenSshErrors = error{
    InvalidSshKey,
    InvalidKeyCount,
};
