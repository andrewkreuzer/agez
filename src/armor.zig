const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const io = std.io;
const window = std.mem.window;

pub const ARMOR_BEGIN_MARKER = "-----BEGIN AGE ENCRYPTED FILE-----";
pub const ARMOR_END_MARKER = "-----END AGE ENCRYPTED FILE-----";

const ARMOR_COLUMNS_PER_LINE = 64;
const ARMOR_BYTES_PER_LINE = ARMOR_COLUMNS_PER_LINE / 4 * 3;

const ARMOR_END_MAP = blk: {
    var map = [_]u8{0} ** 128;
    for (ARMOR_END_MARKER, 1..) |c, i| {
        map[c] = i;
    }
    break :blk map;
};

pub fn isArmorBegin(line: []u8) !bool {
    if (line.len < ARMOR_BEGIN_MARKER.len) return false;
    const slice = line[0..ARMOR_BEGIN_MARKER.len];
    const prefix = ARMOR_BEGIN_MARKER[0..5];
    const full_match = std.mem.eql(u8, slice, ARMOR_BEGIN_MARKER);
    if (std.mem.eql(u8, slice[0..5], prefix) and !full_match) {
        return error.ArmorInvalidMarker;
    }
    return full_match;
}

pub fn isArmorEnd(line: []u8) bool {
    return std.mem.eql(u8, line, ARMOR_END_MARKER);
}

pub fn ArmoredReader(comptime ReaderType: type) type {
    return struct {
        r: ReaderType,
        buf: [ARMOR_BYTES_PER_LINE]u8 = undefined,
        encoded_buf: [ARMOR_COLUMNS_PER_LINE + 1]u8 = undefined,
        start: usize = 0,
        end: usize = 0,

        marker_found: bool = false,

        pub const Error = ReaderType.Error || ArmorError;
        pub const NoEofError = Error || error{
            EndOfStream,
        };
        pub const Reader = io.Reader(*Self, Error, read);

        const Decoder = std.base64.standard.Decoder;

        const Self = @This();

        fn fill(self: *Self) Error!usize {
            if (self.marker_found) return 0;

            var buf: [ARMOR_COLUMNS_PER_LINE]u8 = undefined;
            var n = try self.r.readAll(&buf);
            if (n == 0) return 0;

            var slice = buf[0..n];

            // if we read less than 64 bytes the end
            // marker must be at the end of the buffer
            if (n != ARMOR_COLUMNS_PER_LINE) {
                if (n < ARMOR_END_MARKER.len) return error.ArmorNoEndMarker;
                if (mem.indexOf(u8, slice, ARMOR_END_MARKER)) |start| {
                    var s = start;
                    if (s == 0) return 0;
                    if (slice[s-1] == '\n') s -= 1;
                    if (slice[s-1] == '\r') s -= 1;
                    slice = slice[0..s];
                } else return error.ArmorNoEndMarker;

            } else {
                // our buffer is full we need to check if
                // the last character is in the end marker
                // and walk our way back to the start if so
                const b = slice[n-1];
                var pos = ARMOR_END_MAP[b];
                if (pos != 0) {
                    const start = n - pos;
                    const maybe_marker = slice[start..n];
                    while (pos > 0) {
                        pos -= 1;
                        const c = maybe_marker[pos];
                        // TODO: confirm end marker is correct
                        // currently we just assume it is
                        if (pos < ARMOR_END_MARKER.len and c == '\n') {
                            self.marker_found = true;
                            if (pos > 0 and slice[pos-1] == '\r') pos -= 1;
                            slice = buf[0..start+pos];
                        }
                        if (ARMOR_END_MAP[c] == 0) break;
                    }
                }
            }

            // if we didn't find the end marker
            // check that next byte is a newline
            if (!self.marker_found) {
                var c = self.r.readByte() catch 0;
                if (c == '\r') c = self.r.readByte() catch 0;
                if (c != 0 and c != '\n') return error.ArmorInvalidLine;
            }

            n = Decoder.calcSizeForSlice(slice) catch {
                return error.ArmorDecodeError;
            };
            Decoder.decode(self.buf[0..n], slice) catch {
                return error.ArmorDecodeError;
            };

            return n;
        }

        pub fn read(self: *Self, dest: []u8) Error!usize {
            var current = self.buf[self.start..self.end];
            if (current.len != 0) {
                const n = @min(dest.len, current.len);
                @memcpy(dest[0..n], current[0..n]);
                self.start += n;
                return n;
            }

            self.end = try self.fill();
            const n = @min(dest.len, self.end);
            @memcpy(dest[0..n], self.buf[0..n]);
            self.start = n;
            return n;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub fn ArmoredWriter(comptime WriterType: type) type {
    return struct {
        w: WriterType,
        decoded_buf: [ARMOR_BYTES_PER_LINE]u8 = undefined,
        written: usize = 0,
        end: usize = 0,

        pub const Error = WriterType.Error;
        pub const Writer = io.Writer(*Self, Error, write);

        const Encoder = std.base64.standard.Encoder;

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.end + bytes.len < self.decoded_buf.len) {
                @memcpy(self.decoded_buf[self.end..][0..bytes.len], bytes);
                self.end += bytes.len;
                try self.flushIfNeeded();
                return bytes.len;
            }

            var b = bytes;
            while (b.len != 0) {
                const n = @min(self.decoded_buf.len - self.end, b.len);
                @memcpy(self.decoded_buf[self.end..][0..n], b[0..n]);
                self.end += n;
                b = b[n..];
                try self.flushIfNeeded();
            }
            return self.end;
        }

        fn flushIfNeeded(self: *Self) Error!void {
            if (self.end != self.decoded_buf.len) return;
            try self.flush();
        }

        pub fn flush(self: *Self) Error!void {
            var buf: [ARMOR_COLUMNS_PER_LINE]u8 = undefined;
            const n = Encoder.calcSize(self.decoded_buf[0..self.end].len);
            _ = Encoder.encode(buf[0..n], self.decoded_buf[0..self.end]);
            try self.w.writeAll(buf[0..n]);
            self.written += n + try self.w.write("\n");
            self.end = 0;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub const ArmorError = error{
    ArmorInvalidMarker,
    ArmorInvalidLine,
    ArmorInvalidLineLength,
    ArmorNoEndMarker,
    ArmorDecodeError,
};

test "encode decode" {
    const t = std.testing;
    const words_encoded =
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        \\-----END AGE ENCRYPTED FILE-----
        ;
    const words =
        \\age-encryption.org/v1
        \\-> X25519 xqc9Vz4CWbpWQhRzqtVFTRKPgsoR8wD6kSu0X7ToNHs
        \\5do6iO8z2q0XxD7gR1DUmfBohWP+shpk+jYpxlM/vrM
        \\--- +9cknBKTpL9Jxzm0t3F/+YPoR/RR3Mw7fhSaM2/cI
        ;
    var fbs_decode = std.io.fixedBufferStream(words_encoded);
    const words_reader = fbs_decode.reader();
    var armored_reader = ArmoredReader(@TypeOf(words_reader)){.r = words_reader };
    const reader = armored_reader.reader();
    var buf_decode: [words.len]u8 = undefined;
    var n = try reader.readAll(&buf_decode);

    try t.expectEqualSlices(u8, words, buf_decode[0..n]);

    var buf_encode: [words_encoded.len]u8 = undefined;
    var fbs_encode = std.io.fixedBufferStream(&buf_encode);
    const words_writer = fbs_encode.writer();
    var armored_writer = ArmoredWriter(@TypeOf(words_writer)){.w = words_writer };
    const writer = armored_writer.writer();
    n = try writer.write(words);
    try armored_writer.flush();
    _ = try fbs_encode.write("-----END AGE ENCRYPTED FILE-----");

    try t.expectEqualSlices(u8, words_encoded, buf_encode[0..]);
}

test "invalid header" {
    const t = std.testing;
    const words_encoded =
        \\ Header: not valid
        \\
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        \\-----END AGE ENCRYPTED FILE-----
        ;
    var fbs_decode = std.io.fixedBufferStream(words_encoded);
    const words_reader = fbs_decode.reader();
    var armored_reader = ArmoredReader(@TypeOf(words_reader)){.r = words_reader };
    const reader = armored_reader.reader();
    var buf_decode: [128]u8 = undefined;
    try t.expectError(error.ArmorInvalidLine, reader.readAll(&buf_decode));

}

test "flush" {
    const t = std.testing;
    const words =
        \\a small string
        ;

    var buf_encode: [128]u8 = undefined;
    var fbs_encode = std.io.fixedBufferStream(&buf_encode);
    const words_writer = fbs_encode.writer();
    var armored_writer = ArmoredWriter(@TypeOf(words_writer)){.w = words_writer };
    const writer = armored_writer.writer();

    _ = try writer.write(words);
    try t.expect(armored_writer.written == 0);
    try armored_writer.flush();
    try t.expectEqualSlices(u8, "YSBzbWFsbCBzdHJpbmc=\n", buf_encode[0..armored_writer.written]);
}

test "fill" {
    const t = std.testing;
    const cases = [_]struct {
        data: []const u8,
        expect: []const u8,
    }{
        .{ .data = "" , .expect = "" },
        .{
            .data = 
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
                \\YWdlLWVuY3J5cHRpb24ub3JnL3Yx
                \\-----END AGE ENCRYPTED FILE-----
            , .expect = "age-encryption.org/v1",
        },
        .{
            .data =
                \\YSBzdHJpbmcgdGhhdCBpcyA0NyBieXRlcyBsb25nIHRvIHRlc3QgZW5kIGNhc2U=
                \\-----END AGE ENCRYPTED FILE-----
            , .expect = "a string that is 47 bytes long to test end case"
        },
        .{
            .data =
                \\aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
                \\-----END AGE ENCRYPTED FILE-----
            , .expect = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        },
    };
    for (cases) |case| {
        var fbs = std.io.fixedBufferStream(case.data);
        const fbs_reader = fbs.reader();
        var armored_reader = ArmoredReader(@TypeOf(fbs_reader)){.r = fbs_reader };
        const reader = armored_reader.reader();
        var buf_decode: [512]u8 = undefined;
        const n = try reader.readAll(&buf_decode);

        try t.expectEqualSlices(u8, case.expect, buf_decode[0..n]);
    }
}
