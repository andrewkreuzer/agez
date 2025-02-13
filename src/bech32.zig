const std = @import("std");

// Encoding character set. Maps data value -> char
const ALPHABET = [32]u8{
    'q','p','z','r','y','9','x','8',
    'g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h',
    'c','e','6','m','u','a','7','l'
};

// maps an ascii byte to its index in the charset
const ALPHABET_MAP: [128]i8 = blk: {
    var map = [_]i8{-1} ** 128;
    for (ALPHABET, 0..) |c, i| {
        map[c] = i;
    }
    break :blk map;
};

const seperator: u8 = '1';

const Bech32 = struct {
    hrp: []const u8,
    data: []u8,
};

pub fn encode(out: []u8, hrp: []const u8, data: []const u8) ![]u8 {
    const lower = std.ascii.toLower;
    if (hrp.len + data.len + 7 > 90) { return error.InvalidLength; }
    if (hrp.len < 1) { return error.InvalidHrpLength; }

    var i: usize = 0;
    for (hrp) |c| {
        if (c < 33 or c > 126) {
            return error.InvalidAscii;
        }
        out[i] = lower(c);
        i += 1;
    }
    const _hrp = out[0..i];

    out[hrp.len] = seperator;
    i += 1;

    for (data) |c| {
        out[i] = ALPHABET[lower(c)];
        i += 1;
    }

    const checksum = try createChecksum(_hrp, data);
    for(checksum) |c| {
        out[i] = ALPHABET[c];
        i += 1;
    }

    return out[0..i];
}

pub fn decode(out: []u8, hrp: []const u8, data: []const u8) !Bech32 {
    const sep_idx = try rfind(seperator, data);
    if (data.len > 90) { return error.InvalidLength; }
    if (hrp.len < 1 or hrp.len > 83) { return error.InvalidHrpLength; }
    if (data.len < 8 or data.len > 90) { return error.InvalidDataLength; }
    if (data[sep_idx+1..].len < 6) { return error.InvalidChecksum; }

    const len = data.len;
    @memcpy(out[0..len], data);
    const _hrp = out[0..sep_idx];
    const _data = out[sep_idx+1..len];

    if (!std.mem.eql(u8, hrp, _hrp)) { return error.InvalidHrp; }

    try ascii_sanitization(sep_idx, out[0..data.len]);
    mapToCharSet(_data);
    try verifyChecksum(_hrp, _data);

    return .{
        .hrp = _hrp,
        .data = _data[0.._data.len-6],
    };
}

fn createChecksum(hrp: []const u8, data: []const u8) ![6]u8 {
    var buf: [180]u8 = undefined;
    var idx = expandHrp(&buf, hrp);
    for (data) |*c| {
        buf[idx] = c.*;
        idx += 1;
    }

    for (0..6) |_| {
        buf[idx] = 0;
        idx += 1;
    }

    const plm: u32 = polyMod(buf[0..idx]) ^ 1;
    var checksum: [6]u8 = undefined;
    for (&checksum, 0..) |*c, j| {
        c.* = @intCast((plm >> @as(u5, @intCast((5 - j) * 5))) & 0x1f);
    }

    return checksum;
}

fn verifyChecksum(hrp: []const u8, data: []const u8) !void {
    var buf: [180]u8 = undefined;
    var idx = expandHrp(&buf, hrp);

    for (data) |*c| {
        buf[idx] = c.*;
        idx += 1;
    }

    if (polyMod(buf[0..idx]) != 1) {
        return error.InvalidChecksum;
    }
}

fn polyMod(data: []const u8) u32 {
    const GEN = [5]u32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    var chk: u32 = 1;
    for (data) |c| {
        const b: u8 = @intCast(chk >> 25);
        chk = (chk & 0x1ffffff) << 5 ^ @as(u32, @intCast(c));
        for (0..GEN.len) |i| {
            if ((b >> @as(u3, @intCast(i))) & 1 == 1) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

fn expandHrp(out: []u8, hrp: []const u8) usize {
    var idx: usize = 0;
    for (hrp) |c| {
        out[idx] = c >> 5;
        idx += 1;
    }
    out[idx] = 0;
    idx += 1;
    for (hrp) |c| {
        out[idx] = c & 0x1f;
        idx += 1;
    }
    return idx;
}

fn rfind(char: u8, data: []const u8) !usize {
    var i: usize = data.len - 1;
    while (i > 0) {
        // continuation expresssions are executred at the end of the loop
        // this is a hack so we can actually decrement to 0 without overflow
        i -= 1;
        if (data[i] == char) {
            return i;
        }
    }
    return error.SeparatorNotFound;
}

fn ascii_sanitization(sep_idx: usize, data: []u8) !void {
    var lower: bool = false;
    var upper: bool = false;
    for (data, 0..) |*c, i| {
        // cheack for mixed case and convert to lowercase
        if (c.* >= 'a' and c.* <= 'z') { lower = true; }
        if (c.* >= 'A' and c.* <= 'Z') {
            c.* = std.ascii.toLower(c.*);
            upper = true;
        }
        if (lower and upper) { return error.MixedCase; }

        // ensure our hrp is within our ascii subset
        if (i < sep_idx and (c.* < 33 or c.* > 126)) {
            return error.InvalidAscii;
        }

        // ensure our data is alphanumeric and not in our excluded charset
        if (i > sep_idx) {
            if (!alphanumeric(c.*)) { return error.InvalidAscii; }
            if (excludedCharset(c.*)) { return error.InvalidAscii; }
        }
    }

}

fn alphanumeric(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
}

fn excludedCharset(c: u8) bool {
    return c == '1' or c == 'b' or c == 'i' or c == 'o';
}

pub fn mapToCharSet(data: []u8) void {
    for (data) |*c| {
         c.* = @intCast(ALPHABET_MAP[c.*]);
    }
}

pub fn convertBits(out: []u8, data: []const u8, inbits: u32, outbits: u32, pad: bool) !usize {
    if (outbits > 8 or inbits > 8) { return error.BitConversionError; }
    var i: usize = 0;
    var acc: u32 = 0;
    var bits: u32 = 0;
    const one: u32 = 1;
    const maxv: u32 = (one<<@as(u5, @intCast(outbits))) - 1;
    for (data) |c| {
        const v: u32 = @intCast(c);
        if (v >> @as(u5, @intCast(inbits)) != 0) { return error.BitConversionError; }
        acc = (acc << @as(u5, @intCast(inbits))) | v;
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[i] = @intCast((acc >> @as(u5, @intCast(bits))) & maxv);
            i += 1;
        }
    }
    if (pad) {
        if (bits > 0) {
            out[i] = @intCast((acc << @as(u5, @intCast(outbits - bits))) & maxv);
            i += 1;
        }
    } else if (bits >= inbits or (acc << @as(u5, @intCast(outbits - bits)) & maxv) != 0) {
        return error.BitConversionError;
    }

    return i;
}

const Bech32Error = error{
    InvalidLength,
    InvalidHrp,
    InvalidHrpLength,
    InvalidDataLength,
    InvalidAscii,
    InvalidChecksum,
    MixedCase,
    SeparatorNotFound,
    BitConversionError,
};

test "decode" {
    const cases = [_]struct {
        hrp: []const u8,
        data: []const u8,
        expected: []const u8,
    }{
        .{ .hrp = "A", .data = "A12UEL5L", .expected = &[_]u8{} },
        .{ .hrp = "a", .data = "a12uel5l", .expected = &[_]u8{} },
        .{ .hrp = "bech32", .data = "bech321qpz4nc4pe", .expected = &[_]u8{0,1,2} },
        .{
            .hrp = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            .data = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            .expected = &[_]u8{},
        },
        .{
            .hrp = "abcdef",
            .data = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            .expected = &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 }
        },
        .{
            .hrp = "1",
            .data = "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            .expected = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        },
        .{
            .hrp = "split",
            .data = "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            .expected = &[_]u8{ 24, 23, 25, 24, 22, 28, 1, 16, 11, 29, 8, 25, 23, 29, 19, 13, 16, 23, 29, 22, 25, 28, 1, 16, 11, 3, 25, 29, 27, 25, 3, 3, 29, 19, 11, 25, 3, 3, 25, 13, 24, 29, 1, 25, 3, 3, 25, 13 },
        },
        .{ .hrp = "?", .data = "?1ezyfcl", .expected = &[_]u8{} },
    };

    for (cases) |c| {
        var buf: [180]u8 = undefined;
        const decoded = try decode(&buf, c.hrp, c.data);
        try std.testing.expectEqualSlices(u8, c.expected, decoded.data);
    }
}

test "encode" {
    const cases = [_]struct {
        hrp: []const u8,
        data: []const u8,
        expected: []const u8,
    }{
        .{ .hrp = "A", .expected = "a12uel5l", .data = &[_]u8{} },
        .{ .hrp = "a", .expected = "a12uel5l", .data = &[_]u8{} },
        .{
            .hrp = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            .expected = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            .data = &[_]u8{},
        },
        .{
            .hrp = "abcdef",
            .expected = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            .data = &[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 }
        },
        .{
            .hrp = "1",
            .expected = "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            .data = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        },
        .{
            .hrp = "split",
            .expected = "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            .data = &[_]u8{ 24, 23, 25, 24, 22, 28, 1, 16, 11, 29, 8, 25, 23, 29, 19, 13, 16, 23, 29, 22, 25, 28, 1, 16, 11, 3, 25, 29, 27, 25, 3, 3, 29, 19, 11, 25, 3, 3, 25, 13, 24, 29, 1, 25, 3, 3, 25, 13 },
        },
        .{ .hrp = "?", .expected = "?1ezyfcl", .data = &[_]u8{} },
    };

    for (cases) |c| {
        var buf: [180]u8 = undefined;
        const encoded = try encode(&buf, c.hrp, c.data);
        try std.testing.expectEqualSlices(u8, c.expected, encoded);
    }
}

test "decode_invalid" {
    const cases = [_]struct {
        hrp: []const u8,
        data: []const u8,
        expected: Bech32Error,
    }{
        .{ .hrp = &[_]u8{0x20}, .data = &[_]u8{0x20} ++ "1nwldj5".*, .expected = error.InvalidAscii },
        .{ .hrp = &[_]u8{0x7f}, .data = &[_]u8{0x7f} ++ "1axkwrx".*, .expected = error.InvalidAscii },
        .{ .hrp = &[_]u8{0x80}, .data = &[_]u8{0x80} ++ "1eym55h".*, .expected = error.InvalidAscii },
        .{ .hrp = "", .data = "pzry9x0s0muk", .expected = error.SeparatorNotFound },
        .{ .hrp = "", .data = "1pzry9x0s0muk", .expected = error.InvalidHrpLength },
        .{ .hrp = "x", .data = "x1b4n0q5v", .expected = error.InvalidAscii },
        .{ .hrp = "li", .data = "li1dgmt3", .expected = error.InvalidChecksum },
        .{ .hrp = "de", .data = "de1lg7wt" ++ &[_]u8{0xFF}, .expected = error.InvalidAscii },
        .{ .hrp = "A", .data = "A1G7SGD8", .expected = error.InvalidChecksum },
        .{ .hrp = "", .data = "10a06t8", .expected = error.InvalidHrpLength },
        .{ .hrp = "", .data = "1qzzfhee", .expected = error.InvalidHrpLength },
        .{
            .hrp = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            .data = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            .expected = error.InvalidLength
        },
    };

    for (cases) |c| {
        var buf: [180]u8 = undefined;
        try std.testing.expectError(c.expected, decode(&buf, c.hrp, c.data));
    }
}

test "encode_invalid" {
    const cases = [_]struct {
        hrp: []const u8,
        data: []const u8,
        expected: Bech32Error,
    }{
        .{ .hrp = &[_]u8{0x20}, .data = &[_]u8{}, .expected = error.InvalidAscii },
        .{ .hrp = &[_]u8{0x7f}, .data = &[_]u8{}, .expected = error.InvalidAscii },
        .{ .hrp = &[_]u8{0x80}, .data = &[_]u8{}, .expected = error.InvalidAscii },
        .{ .hrp = "", .data = &[_]u8{1,2,3}, .expected = error.InvalidHrpLength },
        .{
            .hrp = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            .expected = error.InvalidLength,
            .data = &[_]u8{},
        },
    };

    for (cases) |c| {
        var buf: [180]u8 = undefined;
        try std.testing.expectError(c.expected, encode(&buf, c.hrp, c.data));
    }
}

test "roundtrip" {
    const t = std.testing;
    const hrp = "AGE-SECRET-KEY-";
    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";

    var buf: [90]u8 = undefined;
    const decoded = try decode(&buf, hrp, identity);

    var buf2: [90]u8 = undefined;
    const n = try convertBits(&buf2, decoded.data, 5, 8, false);

    var buf3: [90]u8 = undefined;
    const n2 = try convertBits(&buf3, buf2[0..n], 8, 5, true);

    var buf4: [90]u8 = undefined;
    const encoded = try encode(&buf4, hrp, buf3[0..n2]);

    for (encoded) |*c| {
        c.* = std.ascii.toUpper(c.*);
    }

    try t.expectEqualSlices(u8, encoded, identity);
}
