const std = @import("std");
const mem = std.mem;
const ts = std.crypto.timing_safe;
const math = std.math;
const ff = std.crypto.ff;
const os = std.os;

const Uint = ff.Uint(MAX_BITS);
const Modulus = ff.Modulus(MAX_BITS);
const Fe = Modulus.Fe;
const Sha256 = std.crypto.hash.sha2.Sha256;

const MAX_BITS: u32 = 4096;
const MaxPrim = u5120;

pub const KeyPair = struct {
    public_key: PublicKey,
    private_key: SecretKey,

    // TODO: inconsistent naming of private/secret key, pick
    //       one name and keep it, std lib uses SecretKey
    pub fn fromPrivateKey(secret_key: SecretKey) !KeyPair {
        return .{
            .private_key = secret_key,
            .public_key = .{
                .n = secret_key.n,
                .e = secret_key.e,
            },
        };
    }
};

pub const PublicKey = struct {
    n: Modulus,
    e: Fe,

    pub fn fromParts(n: []u8, e: []u8) !PublicKey {
        const _n = try Modulus.fromBytes(n, .big);
        return .{
            .n = _n,
            .e = try Fe.fromBytes(_n, e, .big),
        };
    }

    pub fn encryptOaep(self: *const PublicKey, c: []u8, m: []const u8, label: []const u8) !usize {
        const hash_length = Sha256.digest_length;

        var l: [hash_length]u8 = undefined;
        Sha256.hash(label, &l, .{});

        std.crypto.secureZero(u8, c);
        var payload = c[1..];
        const seed = payload[0..hash_length];
        var db = payload[hash_length..];

        std.crypto.random.bytes(seed);

        @memcpy(db[0..hash_length], &l);
        db[db.len-m.len-1] = 0x01;
        @memcpy(db[db.len-m.len..], m);

        mgf1Xor(db, seed);
        mgf1Xor(seed, db);

        _ = try self.encrypt(c, payload);

        return (self.n.bits() + 7) / 8;
    }


    pub fn encrypt(self: *const PublicKey, c: []u8, m: []const u8) !usize {
        const _m_uint = try Fe.fromBytes(self.n, m, .big);
        const _m = try self.n.pow(_m_uint, self.e);
        try _m.toBytes(c, .big);
        return (self.n.bits() + 7) / 8;
    }

    pub fn size(self: *const PublicKey) u32 {
        return @intCast(@divExact(self.n.bits(), 8));
    }
};

pub const SecretKey = struct {
    n: Modulus,
    e: Fe,
    d: Fe,
    p: Fe,
    q: Fe,
    dp: ?Fe = null,
    dq: ?Fe = null,
    qinv: ?Fe = null,

    pub fn fromParts(
        n: []u8,
        e: []u8,
        d: []u8,
        p: []u8,
        q: []u8,
    ) !SecretKey {
        const _n = try Modulus.fromBytes(n, .big);
        return .{
            .n = _n,
            .e = try Fe.fromBytes(_n, e, .big),
            .d = try Fe.fromBytes(_n, d, .big),
            .p = try Fe.fromBytes(_n, p, .big),
            .q = try Fe.fromBytes(_n, q, .big),
        };
    }

    pub fn publicKey(self: *const SecretKey) PublicKey {
        return .{
            .n = self.n,
            .e = self.e,
        };
    }

    pub fn validate(self: *SecretKey) !bool {
        if (self.p.isZero() or self.q.isZero()) return false;
        if (!self.n.mul(self.p, self.q).eql(self.n.zero)) {
            return false;
        }

        // TOOD: bytes please
        const de, const overflow = @mulWithOverflow(
            try self.d.toPrimitive(MaxPrim),
            try self.e.toPrimitive(MaxPrim),
        );
        if (overflow != 0) return error.Overflow;
        const de_uint = try Uint.fromPrimitive(MaxPrim, de);

        var p_m1_mod = try Modulus.fromUint(self.p.v);
        _ = p_m1_mod.v.subWithOverflow(p_m1_mod.one().v);
        const p1 = p_m1_mod.reduce(de_uint);
        if (!p1.eql(p_m1_mod.one())) {
            return false;
        }

        var q_m1_mod = try Modulus.fromUint(self.q.v);
        _ = q_m1_mod.v.subWithOverflow(q_m1_mod.one().v);
        const q1 = q_m1_mod.reduce(de_uint);
        if (!q1.eql(q_m1_mod.one())) {
            return false;
        }
        return true;
    }

    pub fn precompute(self: *SecretKey) !void {
        var p_m1_mod = try Modulus.fromUint(self.p.v);
        _ = p_m1_mod.v.subWithOverflow(p_m1_mod.one().v);

        var q_m1_mod = try Modulus.fromUint(self.q.v);
        _ = q_m1_mod.v.subWithOverflow(q_m1_mod.one().v);

        const dp = p_m1_mod.reduce(self.d.v);
        const dq = q_m1_mod.reduce(self.d.v);

        // use fermat's little theorem to calculate qinv
        // inspired by golang's implementation
        const one = self.n.one().v;
        var p_m2_fe = self.p;
        _ = p_m2_fe.v.subWithOverflow(one);
        _ = p_m2_fe.v.subWithOverflow(one);

        var p_mod = try Modulus.fromUint(self.p.v);
        const q2 = self.q.v;
        const q_fe = p_mod.reduce(q2);
        const qinv = try p_mod.pow(q_fe, p_m2_fe);

        self.dp = dp;
        self.dq = dq;
        self.qinv = qinv;
    }

    pub fn encryptOaep(self: *const SecretKey, c: []u8, m: []const u8, label: []const u8) !usize {
        const pk = self.publicKey();
        pk.encryptOaep(c, m, label);
    }

    pub fn encrypt(self: *const SecretKey, c: []u8, m: []u8) !usize {
        const pk = self.publicKey();
        pk.encrypt(c, m);
    }

    fn select(v: usize, x: usize, y: usize) usize { return ~(v-%1)&x | (v-%1)&y; }

    pub fn decryptOaep(self: *const SecretKey, m: []u8, c: []const u8, label: []const u8) !void {
        const hash_length = Sha256.digest_length;
        var bytes: [4096]u8 = undefined;
        const n = try self.decrypt(&bytes, c);
        const _m = bytes[bytes.len-n..];

        var l1: [hash_length]u8 = undefined;
        Sha256.hash(label, &l1, .{});

        const first_bytes = _m[0..1].*;
        const first_byte_check = @intFromBool(ts.eql([1]u8, first_bytes, [_]u8{0}));

        const seed = _m[1..1+hash_length];
        const db = _m[1+hash_length..];

        mgf1Xor(seed, db);
        mgf1Xor(db, seed);

        const l2 = db[0..hash_length].*;
        const hash_check = @intFromBool(ts.eql([hash_length]u8, l1, l2));

        const out = db[hash_length..];
        var index: usize = ~@as(usize, 0);
        var looking: usize = 1;
        var invalid: usize = 0;
        for (out, 0..) |b, i| {
            const zero = @intFromBool(ts.eql([1]u8, [_]u8{b}, [_]u8{0}));
            const one = @intFromBool(ts.eql([1]u8, [_]u8{b}, [_]u8{1}));
            index = select(looking&one, i, index);
            looking &= ~one;
            invalid |= looking & ~zero;
        }

        if (first_byte_check&hash_check&~invalid&~looking != 1) {
            return error.InvalidOaepPadding;
        }

        @memcpy(m, out[index+1..]);
    }

    pub fn decrypt(self: *const SecretKey, m: []u8, c: []const u8) !usize {
        var p_mod = try Modulus.fromUint(self.p.v);
        const q_mod = try Modulus.fromUint(self.q.v);
        const _c_uint = try Uint.fromBytes(c, .big);

        // m1 = c^dp mod p
        const m1 = try p_mod.pow(p_mod.reduce(_c_uint), self.dp.?);

        // m2 = c^dq mod q
        var m2 = try q_mod.pow(q_mod.reduce(_c_uint), self.dq.?);

        // h = qinv * (m1 - m2) mod p
        const m1_minus_m2 = p_mod.sub(m1, p_mod.reduce(m2.v));
        var h = p_mod.mul(p_mod.reduce(m1_minus_m2.v), self.qinv.?);

        // expand h & m2 to the size of n
        h.v.limbs_len = self.n.v.limbs_len;
        m2.v.limbs_len = self.n.v.limbs_len;

        // m = m2 + hq
        const hq = self.n.mul(h, self.q);
        const _m = self.n.add(m2, hq);

        try _m.toBytes(m, .big);

        return (self.n.bits() + 7) / 8;
    }

    pub fn size(self: *const SecretKey) u32 {
        return @intCast(@divExact(self.n.bits(), 8) + 7);
    }
};

fn mgf1Xor(dst: []u8, seed: []u8) void {
    var counter: u32 = 0;
    var i: usize = 0;
    var c: [4]u8 = undefined;
    while (i < dst.len) {
        mem.writeInt(u32, &c, counter, .big);

        var sha256 = Sha256.init(.{});
        sha256.update(seed);
        sha256.update(&c);
        const digest = sha256.finalResult();

        const remaining = @min(digest.len, dst.len - i);
        for (digest[0..remaining]) |b| {
            dst[i] ^= b;
            i += 1;
        }
        counter += 1;
    }
}

const RsaErrors = error{
    InvalidRsaKey,
    InvalidOaepPadding,
    Overflow,
};

fn test_key() !SecretKey {
    var n = [_]u8{
          0, 191, 196, 250, 169, 243, 223, 187,  14, 190, 125, 126, 159, 255, 181, 36,
          7, 114,  57,   3, 229,  86,  41, 251,  74,  93, 191, 200,  93, 212, 253, 96,
        117, 208, 230,   1, 229, 233,  28,  66, 122, 169, 203,  78,  77, 237, 134, 240,
         74, 195, 115, 136, 255, 159,  14, 145,  16, 210, 206, 136,  52, 209,  42, 131,
         98, 192, 167, 168,  55, 178, 124, 134, 178, 171,  92,  51, 135,  43,  32, 248,
        126, 162, 221, 130, 249, 115,  18, 194,  67, 125, 250,   1,  87, 215, 172, 230,
        109,  11,  53, 101, 223, 117, 168, 119, 150, 220,   8, 134,  10, 251, 202,  95,
        107,  18, 234, 161,  90, 194,  71, 161, 156, 114,  84, 133, 159, 187,  26, 132,
        171
    };
    var e = [_]u8{1, 0, 1};
    var d = [_]u8{
          0, 168, 117, 190, 137,  59, 141, 199, 129, 253,  62, 186, 212, 140, 201, 176,
         91, 198,  48, 101, 198, 185, 249, 105,  33, 123, 215, 116, 137,  81,   8,  64,
         11,  95,  54,  30, 102, 188, 111, 177, 202, 149, 139, 222,  62, 192, 176, 240,
         55, 141,  24, 218,  57,  75, 157, 125,  59, 221,  35, 199,  45,  54, 173, 116,
        249, 234, 241, 156,  63, 187,  71, 233, 141, 116, 252, 105,  28,  65,  33, 147,
         65, 191, 213,  61, 122, 152, 129, 135,  22, 244, 121,  84,  14,  43,  44, 241,
         25, 163, 223, 133, 200, 145,  83, 252, 106, 222, 146,  85, 221, 217, 155,   3,
        182, 226,  13,  54,  54, 146,  99,  35, 100, 110,  65, 227, 157,  51, 132, 225,
        185
    };
    var p = [_]u8{
          0, 255, 103, 102, 104, 72, 239, 199, 148,  50, 225, 136, 172,  12, 184, 254,
          9, 252, 213,   9, 219,  8, 198, 181, 145,  42, 124, 117,  46, 118, 185,  25,
        148, 209,  90,  79, 199, 131,  95,  61, 138, 180, 61,  67, 177,  92, 178, 245,
        203, 197,  50,  76, 155,  44, 225, 197, 133, 201, 229, 128, 40,  87, 221, 101,
        253
    };
    var q = [_]u8{
          0, 192,  55, 142, 249, 246, 246, 252, 201, 214, 197, 140, 147,  84, 152,  29,
        205,   7, 203,  33,  54, 139,   1, 158,  77,  19, 188, 176,  36,  89,  54, 241,
        161,  35, 254, 196, 156, 179, 160,  24,   5, 168, 172, 253,  24, 187, 188, 210,
        198,   1,  13, 234,  73, 110, 187,  23,  28, 122, 239,  13,   3,  16, 247,  65,
        199
    };

    var sk = try SecretKey.fromParts(&n, &e, &d, &p, &q);
    try std.testing.expect(try sk.validate());
    try sk.precompute();

    return sk;
}

test "round trip" {
    const secret_key = try test_key();
    const public_key = secret_key.publicKey();

    const message = "test";
    var c: [128]u8 = undefined;
    _ = try public_key.encrypt(&c, message);

    var m: [128]u8 = undefined;
    _ = try secret_key.decrypt(&m, &c);

    try std.testing.expectEqualStrings(message, m[m.len-message.len..]);
}

test "round trip oaep" {
    const secret_key = try test_key();
    const public_key = secret_key.publicKey();

    const message = "test";
    var c: [128]u8 = undefined;
    _ = try public_key.encryptOaep(&c, message, "test");

    var m: [4]u8 = undefined;
    _ = try secret_key.decryptOaep(&m, &c, "test");

    try std.testing.expectEqualStrings(message, m[m.len-message.len..]);
}
