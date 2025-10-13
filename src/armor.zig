const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const isWhitespace = std.ascii.isWhitespace;
const mem = std.mem;
const window = std.mem.window;

pub const header = "-----BEGIN AGE ENCRYPTED FILE-----";
pub const footer = "-----END AGE ENCRYPTED FILE-----";

// Follows RFC7468 (https://www.rfc-editor.org/rfc/rfc7468)
// Generators MUST wrap the base64-encoded lines so that each line
// consists of exactly 64 characters except for the final line, which
// will encode the remainder of the data (within the 64-character line
// boundary), and they MUST NOT emit extraneous whitespace.  Parsers MAY
// handle other line sizes.  These requirements are consistent with PEM
// [RFC1421].
pub const columns_per_line = 64;
pub const bytes_per_line = columns_per_line / 4 * 3;

pub const ArmorError = error{
    ArmorInvalidMarker,
    ArmorInvalidLine,
    ArmorInvalidLineLength,
    ArmorNoEndMarker,
    ArmorNoBeginMarker,
    ArmorDecodeError,
};

pub fn isArmorBegin(line: []const u8) error{ArmorInvalidMarker}!bool {
    if (line.len < header.len) return false;
    const slice = line[0..header.len];
    const prefix = header[0..5];
    const full_match = std.mem.eql(u8, slice, header);
    if (std.mem.eql(u8, slice[0..5], prefix) and !full_match) {
        return error.ArmorInvalidMarker;
    }
    return full_match;
}

pub fn isArmorEnd(line: []const u8) error{ArmorInvalidMarker}!bool {
    if (line.len != footer.len) {
        @branchHint(.likely);
        return false;
    }
    const slice = line[0..footer.len];
    const prefix = footer[0..5];
    const full_match = std.mem.eql(u8, slice, footer);
    if (std.mem.eql(u8, slice[0..5], prefix) and !full_match) {
        return error.ArmorInvalidMarker;
    }
    return full_match;
}

const Decoder = std.base64.standard.Decoder;
const Encoder = std.base64.standard.Encoder;

pub const Reader = struct {
    const Self = @This();
    input: *Io.Reader,
    interface: Io.Reader,
    state: State = .header,
    decode_err: ?anyerror = null,
    armor_err: ?ArmorError = null,

    const State = enum {
        header,
        block,
        footer,
    };

    pub fn init(input: *Io.Reader, buffer: []u8) Self {
        assert(buffer.len >= 48);
        return Self{
            .input = input,
            .interface = .{
                .vtable = &.{
                    .readVec = Reader.readVec,
                    .stream = Reader.stream,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    pub fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const first = data[0];
        if (first.len >= 48) {
            var writer: Io.Writer = .{
                .buffer = first,
                .end = 0,
                .vtable = &.{ .drain = Io.Writer.fixedDrain },
            };
            const limit: Io.Limit = .limited(writer.buffer.len - writer.end);
            return r.vtable.stream(r, &writer, limit) catch |err| switch (err) {
                error.WriteFailed => unreachable,
                else => |e| return e,
            };
        }
        try r.rebase(48);
        var writer: Io.Writer = .{
            .buffer = r.buffer,
            .end = r.end,
            .vtable = &.{ .drain = Io.Writer.fixedDrain },
        };
        const limit: Io.Limit = .limited(writer.buffer.len - writer.end);
        r.end += r.vtable.stream(r, &writer, limit) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            else => |e| return e,
        };
        return 0;
    }


    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const ar: *Self = @alignCast(@fieldParentPtr("interface", r));
        const in = ar.input;

        assert(ar.armor_err == null);
        assert(ar.decode_err == null);
        if (in.buffer.len == 0)
            return error.EndOfStream;

        var acc: usize = 0;
        state: switch (ar.state) {
            .header => {
                while (in.takeDelimiterExclusive('\n')) |line| {
                    if (isArmorBegin(line) catch |e| {
                        ar.armor_err = e;
                        return error.ReadFailed;
                    }) {
                        ar.state = .block;
                        continue :state .block;
                    }
                    for (line) |b| if (!isWhitespace(b)) {
                        ar.armor_err = error.ArmorInvalidLine;
                        return error.ReadFailed;
                    };
                } else |err| switch (err) {
                    else => |e| return e,
                    error.StreamTooLong => return error.ReadFailed,
                    error.EndOfStream => {
                        ar.armor_err = error.ArmorNoBeginMarker;
                        return error.ReadFailed;
                    },
                }
            },
            .block => {
                const line_full = in.takeDelimiterExclusive('\n')
                    catch |err| switch (err) {
                        else => |e| return e,
                        error.StreamTooLong => return error.ReadFailed,
                        error.EndOfStream => {
                            ar.armor_err = error.ArmorNoEndMarker;
                            return error.ReadFailed;
                    },
                };

                const line = mem.trimEnd(u8, line_full, "\r");

                if (line.len > columns_per_line) {
                    ar.armor_err = error.ArmorInvalidLineLength;
                    return error.ReadFailed;
                }

                const n = Decoder.calcSizeForSlice(line) catch |e| {
                    ar.decode_err = e;
                    ar.armor_err = error.ArmorInvalidLine;
                    return error.ReadFailed;
                };

                const dest = limit.slice(try w.writableSliceGreedy(n));
                Decoder.decode(dest[0..n], line) catch |e| switch (e) {
                    else => { ar.decode_err = e; return error.WriteFailed; },
                    error.InvalidCharacter,
                    error.InvalidPadding => {
                        ar.decode_err = e;
                        ar.armor_err = error.ArmorInvalidLine;
                        return error.ReadFailed;
                    }
                };

                acc += n;
                w.advance(n);

                const next = in.peekDelimiterExclusive('\n') catch |err| switch (err) {
                    else => |e| return e,
                    error.StreamTooLong => return error.ReadFailed,
                    error.EndOfStream => {
                        ar.armor_err = error.ArmorNoEndMarker;
                        return error.ReadFailed;
                    },
                };

                if (mem.indexOf(u8, next, footer)) |_| {
                    ar.state = .footer;
                    continue :state .footer;
                } else {
                    if (line.len < columns_per_line) {
                        ar.armor_err = error.ArmorInvalidLine;
                        return error.ReadFailed;
                    }
                }
            },
            .footer => {
                while (in.takeDelimiterExclusive('\n')) |line_full| {
                    const line = mem.trimEnd(u8, line_full, "\r");

                    if (isArmorEnd(line) catch |e| {
                        ar.armor_err = e;
                        return error.ReadFailed;
                    }) return acc;

                    for (line) |b| if (!isWhitespace(b)) {
                        ar.armor_err = error.ArmorInvalidLine;
                        return error.ReadFailed;
                    };
                } else |err| switch (err) {
                    else => |e| return e,
                    error.StreamTooLong => return error.ReadFailed,
                }
            },
        }

        return acc;
    }
};

pub const Writer = struct {
    const Self = @This();
    output: *Io.Writer,
    interface: Io.Writer,
    done: bool = false,

    pub fn init(w: *Io.Writer, buffer: []u8) Self {
        assert(buffer.len >= 48);
        return Self{
            .output = w,
            .interface = .{
                .vtable = &.{
                    .drain = Writer.drain,
                    .flush = Writer.flush,
                },
                .buffer = buffer,
                .end = 0,
            }
        };
    }

    pub fn begin(self: *Self) error{WriteFailed}!void {
        return self.output.writeAll(header ++ "\n");
    }

    pub fn finish(self: *Self) error{WriteFailed}!void {
        self.done = true;
        try flush(&self.interface);
        return self.output.writeAll(footer ++ "\n");
    }

    fn flush(w: *Io.Writer) error{WriteFailed}!void {
        const aw: *Writer = @alignCast(@fieldParentPtr("interface", w));
        if (!aw.done) {
            const drainFn = w.vtable.drain;
            while (w.end != 0) _ = try drainFn(w, &.{""}, 1);
        }
        if (aw.interface.end != 0) {
            const end = aw.interface.end;
            const buffer = aw.interface.buffer[0..end];
            var iter = window(u8, buffer, 48, 48);
            while (iter.next()) |line| {
                const buf = try aw.output.writableSliceGreedy(line.len);
                const result = Encoder.encode(buf, line);
                aw.output.advance(result.len);
                _ = try aw.output.write("\n");
            }
            aw.interface.end = 0;
        }
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
        _ = splat;
        const aw: *Writer = @alignCast(@fieldParentPtr("interface", w));
        const output: *Io.Writer = aw.output;
        if (aw.done) return error.WriteFailed;

        var acc: usize = 0;
        var i: usize = 0;
        var n: usize = 0;
        while (i < data.len) {
            var remaining: usize = w.buffer.len - w.end;
            if (remaining != 0) {
                const slice = data[i][n..];
                const to_copy = @min(remaining, slice.len);
                @memcpy(w.buffer[w.end..][0..to_copy], slice[0..to_copy]);
                acc += to_copy;
                w.end += to_copy;
                remaining -= to_copy;
                if (to_copy == slice.len) {
                    i += 1;
                    n = 0;
                } else {
                    n += to_copy;
                }
            }
            var iter = window(u8, w.buffer[0..w.end], 48, 48);
            while (iter.next()) |line| {
                if (line.len < 48) {
                    @memmove(w.buffer[0..line.len], line);
                    remaining = line.len;
                    break;
                }
                const buf = try output.writableSliceGreedy(line.len);
                const result = Encoder.encode(buf, line);
                output.advance(result.len);
                _ = try output.write("\n");
            }
            // buffer could still contain residual
            // data that is not a full line we will
            // flush it when finish is called
            w.end = remaining;
        }

        return acc;
    }
};

test Reader {
    const t = std.testing;
    const words_encoded =
        \\-----BEGIN AGE ENCRYPTED FILE-----
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        \\-----END AGE ENCRYPTED FILE-----
        \\
        ;
    const words =
        \\age-encryption.org/v1
        \\-> X25519 xqc9Vz4CWbpWQhRzqtVFTRKPgsoR8wD6kSu0X7ToNHs
        \\5do6iO8z2q0XxD7gR1DUmfBohWP+shpk+jYpxlM/vrM
        \\--- +9cknBKTpL9Jxzm0t3F/+YPoR/RR3Mw7fhSaM2/cI
        ;

    var r: Io.Reader = .fixed(words_encoded);
    var buf: [48]u8 = undefined;
    var ar: Reader = .init(&r, &buf);
    var buf_decode: [words.len]u8 = undefined;
    try ar.interface.readSliceAll(&buf_decode);

    try t.expectEqualSlices(u8, words, buf_decode[0..]);
}

test Writer {
    const t = std.testing;
    const words_encoded =
        \\-----BEGIN AGE ENCRYPTED FILE-----
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        \\-----END AGE ENCRYPTED FILE-----
        \\
        ;
    const words =
        \\age-encryption.org/v1
        \\-> X25519 xqc9Vz4CWbpWQhRzqtVFTRKPgsoR8wD6kSu0X7ToNHs
        \\5do6iO8z2q0XxD7gR1DUmfBohWP+shpk+jYpxlM/vrM
        \\--- +9cknBKTpL9Jxzm0t3F/+YPoR/RR3Mw7fhSaM2/cI
        ;

    var buf_encode: [words_encoded.len]u8 = undefined;
    var w: Io.Writer = .fixed(&buf_encode);
    var buf: [48]u8 = undefined;
    var aw: Writer = .init(&w, &buf);
    try aw.begin();
    try aw.interface.writeAll(words);
    try aw.finish();

    try t.expectEqualSlices(u8, words_encoded, buf_encode[0..]);
}

test "garbage before begin" {
    const t = std.testing;
    const words_encoded =
        \\garbage
        \\-----BEGIN AGE ENCRYPTED FILE-----
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        \\-----END AGE ENCRYPTED FILE-----
        \\
        ;
    var r: std.Io.Reader = .fixed(words_encoded);
    var buf: [48]u8 = undefined;
    var ar: Reader = .init(&r, &buf);
    var buf_decode: [8]u8 = undefined;
    try t.expectError(error.ReadFailed, ar.interface.readSliceAll(&buf_decode));
    try std.testing.expectError(error.ArmorInvalidLine, ar.armor_err orelse {});
}

test "garbage after begin" {
    const t = std.testing;
    const words_encoded =
        \\-----BEGIN AGE ENCRYPTED FILE-----
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        \\-----END AGE ENCRYPTED FILE-----
        \\garbage
        ;
    var r: std.Io.Reader = .fixed(words_encoded);
    var buf: [48]u8 = undefined;
    var ar: Reader = .init(&r, &buf);
    var buf_decode: [256]u8 = undefined;
    try t.expectError(error.ReadFailed, ar.interface.readSliceAll(&buf_decode));
    try std.testing.expectError(error.ArmorInvalidLine, ar.armor_err orelse {});
}

test "decode" {
    const t = std.testing;
    const cases = [_]struct {
        data: []const u8,
        expect: []const u8,
    }{
        .{ .data = "" , .expect = "" },
        .{
            .data =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\IkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNj
                \\aW5nIGVsaXQsCnNlZCBkbyBlaXVzbW9kIHRlbXBvciBpbmNpZGlkdW50IHV0IGxh
                \\Ym9yZSBldCBkb2xvcmUgbWFnbmEKYWxpcXVhLiBVdCBlbmltIGFkIG1pbmltIHZl
                \\bmlhbSwgcXVpcyBub3N0cnVkIGV4ZXJjaXRhdGlvbgp1bGxhbWNvIGxhYm9yaXMg
                \\bmlzaSB1dCBhbGlxdWlwIGV4IGVhIGNvbW1vZG8gY29uc2VxdWF0LgpEdWlzIGF1
                \\dGUgaXJ1cmUgZG9sb3IgaW4gcmVwcmVoZW5kZXJpdCBpbiB2b2x1cHRhdGUgdmVs
                \\aXQgZXNzZQpjaWxsdW0gZG9sb3JlIGV1IGZ1Z2lhdCBudWxsYSBwYXJpYXR1ci4g
                \\RXhjZXB0ZXVyIHNpbnQgb2NjYWVjYXQKY3VwaWRhdGF0IG5vbiBwcm9pZGVudCwg
                \\c3VudCBpbiBjdWxwYSBxdWkgb2ZmaWNpYSBkZXNlcnVudCBtb2xsaXQKYW5pbSBp
                \\ZCBlc3QgbGFib3J1bS4i
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .expect =
                \\"Lorem ipsum dolor sit amet, consectetur adipiscing elit,
                \\sed do eiusmod tempor incididunt ut labore et dolore magna
                \\aliqua. Ut enim ad minim veniam, quis nostrud exercitation
                \\ullamco laboris nisi ut aliquip ex ea commodo consequat.
                \\Duis aute irure dolor in reprehenderit in voluptate velit esse
                \\cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat
                \\cupidatat non proident, sunt in culpa qui officia deserunt mollit
                \\anim id est laborum."
        },
        .{
            .data =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\YWdlLWVuY3J5cHRpb24ub3JnL3Yx
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .expect = "age-encryption.org/v1",
        },
        .{
            .data =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\YSBzdHJpbmcgdGhhdCBpcyA0NyBieXRlcyBsb25nIHRvIHRlc3QgZW5kIGNhc2U=
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .expect = "a string that is 47 bytes long to test end case"
        },
        .{
            .data =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .expect = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        },
    };
    for (cases) |case| {
        var r: Io.Reader = .fixed(case.data);
        var buf: [48]u8 = undefined;
        var ar: Reader = .init(&r, &buf);
        var buf_decode: [1024]u8 = undefined;
        const n = try ar.interface.readSliceShort(&buf_decode);

        try t.expectEqualSlices(u8, case.expect, buf_decode[0..n]);
    }
}

test "encode" {
    const t = std.testing;
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        data: []const u8,
        expect: []const u8,
    }{
        .{
            .expect =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\IkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNj
                \\aW5nIGVsaXQsCnNlZCBkbyBlaXVzbW9kIHRlbXBvciBpbmNpZGlkdW50IHV0IGxh
                \\Ym9yZSBldCBkb2xvcmUgbWFnbmEKYWxpcXVhLiBVdCBlbmltIGFkIG1pbmltIHZl
                \\bmlhbSwgcXVpcyBub3N0cnVkIGV4ZXJjaXRhdGlvbgp1bGxhbWNvIGxhYm9yaXMg
                \\bmlzaSB1dCBhbGlxdWlwIGV4IGVhIGNvbW1vZG8gY29uc2VxdWF0LgpEdWlzIGF1
                \\dGUgaXJ1cmUgZG9sb3IgaW4gcmVwcmVoZW5kZXJpdCBpbiB2b2x1cHRhdGUgdmVs
                \\aXQgZXNzZQpjaWxsdW0gZG9sb3JlIGV1IGZ1Z2lhdCBudWxsYSBwYXJpYXR1ci4g
                \\RXhjZXB0ZXVyIHNpbnQgb2NjYWVjYXQKY3VwaWRhdGF0IG5vbiBwcm9pZGVudCwg
                \\c3VudCBpbiBjdWxwYSBxdWkgb2ZmaWNpYSBkZXNlcnVudCBtb2xsaXQKYW5pbSBp
                \\ZCBlc3QgbGFib3J1bS4i
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .data =
                \\"Lorem ipsum dolor sit amet, consectetur adipiscing elit,
                \\sed do eiusmod tempor incididunt ut labore et dolore magna
                \\aliqua. Ut enim ad minim veniam, quis nostrud exercitation
                \\ullamco laboris nisi ut aliquip ex ea commodo consequat.
                \\Duis aute irure dolor in reprehenderit in voluptate velit esse
                \\cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat
                \\cupidatat non proident, sunt in culpa qui officia deserunt mollit
                \\anim id est laborum."
        },
        .{
            .expect =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\YWdlLWVuY3J5cHRpb24ub3JnL3Yx
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .data = "age-encryption.org/v1",
        },
        .{
            .expect =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\YSBzdHJpbmcgdGhhdCBpcyA0NyBieXRlcyBsb25nIHRvIHRlc3QgZW5kIGNhc2U=
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .data = "a string that is 47 bytes long to test end case"
        },
        .{
            .expect =
                \\-----BEGIN AGE ENCRYPTED FILE-----
                \\aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
                \\-----END AGE ENCRYPTED FILE-----
                \\
            , .data = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        },
    };
    for (cases) |case| {
        var buf_encode: []u8 = try allocator.alloc(u8, case.expect.len);
        defer allocator.free(buf_encode);
        var w: Io.Writer = .fixed(buf_encode);
        var buf: [48]u8 = undefined;
        var aw: Writer = .init(&w, &buf);
        try aw.begin();
        _ = try aw.interface.write(case.data);
        try aw.finish();
        try w.flush();

        try t.expectEqualSlices(u8, case.expect, buf_encode[0..w.end]);
    }
}
