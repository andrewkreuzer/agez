const std = @import("std");
const assert = std.debug.assert;
const io = std.io;
const window = std.mem.window;

pub const armor_begin_marker = "-----BEGIN AGE ENCRYPTED FILE-----";
pub const armor_end_marker = "-----END AGE ENCRYPTED FILE-----";
const armor_columns_per_line = 64;
const armor_bytes_per_line = armor_columns_per_line / 4 * 3;

const armor_end_map = blk: {
    var map = [_]u8{0} ** 128;
    for (armor_end_marker, 1..) |c, i| {
        map[c] = i;
    }
    break :blk map;
};

pub fn isArmorBegin(line: []u8) bool {
    return std.mem.eql(u8, line, armor_begin_marker);
}

pub fn isArmorEnd(line: []u8) bool {
    return std.mem.eql(u8, line, armor_end_marker);
}

pub fn ArmoredReader(comptime ReaderType: type) type {
    return struct {
        r: ReaderType,
        buf: [armor_bytes_per_line]u8 = undefined,
        encoded_buf: [armor_columns_per_line + 1]u8 = undefined,
        start: usize = 0,
        end: usize = 0,

        marker_found: bool = false,

        pub const Error = ReaderType.Error;
        pub const NoEofError = Error || error{
            EndOfStream,
        };
        pub const Reader = io.Reader(*Self, Error, read);

        const Decoder = std.base64.standard.Decoder;

        const Self = @This();

        //-rw-r--r-- 1 akreuzer users 2.4G Mar  1 18:51 /tmp/age-test.age
        //./zig-out/bin/agez -i id -d /tmp/age-test.age > /dev/null  9.58s user 0.45s system 99% cpu 10.059 total
        fn fill(self: *Self) Error!usize {
            const line = if (
                self.r.readUntilDelimiterOrEof(self.encoded_buf[0..], '\n') catch |err| {
                    std.debug.print("Error reading line: {any}\n", .{err});
                    return 0;
            }) |l| l else "";

            if (std.mem.eql(u8, line, armor_end_marker)) return 0;

            const n = Decoder.calcSizeForSlice(line) catch |err| {
                std.debug.print("Error calculating size: {any}\n", .{err});
                return 0;
            };
            Decoder.decode(self.buf[0..n], line) catch |err| {
                std.debug.print("Error decoding: {any}\n", .{err});
                return 0;
            };
            return n;
        }

        //-rw-r--r-- 1 akreuzer users 2.4G Mar  1 18:51 /tmp/age-test.age
        //./zig-out/bin/agez -i id -d /tmp/age-test.age > /dev/null  3.36s user 0.39s system 99% cpu 3.756 total
        fn fill2(self: *Self) Error!usize {
            var buf = [_]u8{0} ** armor_columns_per_line;

            if (self.marker_found) return 0;
            var n = try self.r.readAll(&buf);
            var slice = buf[0..n];
            if (n == 0) return 0;


            var c = self.r.readByte() catch |err| switch (err) {
                error.EndOfStream => 0,
                else => unreachable, //TODO: probably reachable
            };
            if (c == 0 and n >= armor_end_marker.len) {
                const start = n - armor_end_marker.len;
                const marker = if (slice[n-1] == '\n')
                    slice[start-1..n-1] else slice[start..n];
                if (std.mem.eql(u8, marker, armor_end_marker)) {
                    slice = buf[0..start-1];
                } else unreachable;
            }

            else if (n != armor_columns_per_line) {
                const start = n - armor_end_marker.len;
                const marker = if (slice[n-1] == '\n')
                    slice[start-1..n-1] else slice[start..n];
                if (std.mem.eql(u8, marker, armor_end_marker)) {
                    slice = buf[0..start-1];
                } else unreachable;

            } else {
                c = slice[n-1];
                var pos = armor_end_map[c];
                if (pos != 0) {
                    const start = n - pos;
                    const maybe_marker = slice[start..n];
                    while (pos > 0) {
                        pos -= 1;
                        const chr = maybe_marker[pos];
                        if (pos < armor_end_marker.len and chr == '\n') self.marker_found = true;
                        if (armor_end_map[chr] == 0) break;
                    }
                    if (self.marker_found) {
                        slice = buf[0..start+pos];
                    }
                }
            }

            n = Decoder.calcSizeForSlice(slice) catch |err| {
                std.debug.print("Error calculating size: {any}\n", .{err});
                return 0;
            };
            Decoder.decode(self.buf[0..n], slice) catch |err| {
                std.debug.print("Error decoding: {any}\n", .{err});
                return 0;
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

            self.end = try self.fill2();
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
        decoded_buf: [armor_bytes_per_line]u8 = undefined,
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
            var buf = [_]u8{0} ** armor_columns_per_line;
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
    ArmorInvalidLineLength,
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
    var buf_decode = [_]u8{0} ** words.len;
    var n = try reader.readAll(&buf_decode);

    try t.expectEqualSlices(u8, words, buf_decode[0..n]);

    var buf_encode = [_]u8{0} ** words_encoded.len;
    var fbs_encode = std.io.fixedBufferStream(&buf_encode);
    const words_writer = fbs_encode.writer();
    var armored_writer = ArmoredWriter(@TypeOf(words_writer)){.w = words_writer };
    const writer = armored_writer.writer();
    n = try writer.write(words);
    try armored_writer.flush();
    _ = try fbs_encode.write("-----END AGE ENCRYPTED FILE-----");

    try t.expectEqualSlices(u8, words_encoded, buf_encode[0..]);
}

test "flush" {
    const t = std.testing;
    const words =
        \\a small string
        ;

    var buf_encode = [_]u8{0} ** 128;
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
                ,
            .expect =
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
                ,
                .expect =
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
                ,
                .expect =
                    \\age-encryption.org/v1
            },
            .{
                .data =
                \\aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
                \\-----END AGE ENCRYPTED FILE-----
                ,
                .expect = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        },
    };
    for (cases) |case| {
        var fbs = std.io.fixedBufferStream(case.data);
        const fbs_reader = fbs.reader();
        var armored_reader = ArmoredReader(@TypeOf(fbs_reader)){.r = fbs_reader };
        const reader = armored_reader.reader();
        var buf_decode = [_]u8{0} ** 512;
        const n = try reader.readAll(&buf_decode);

    try t.expectEqualSlices(u8, case.expect, buf_decode[0..n]);
}
}
