const std = @import("std");
const assert = std.debug.assert;
const io = std.io;
const window = std.mem.window;

pub const armor_begin_marker = "-----BEGIN AGE ENCRYPTED FILE-----";
pub const armor_end_marker = "-----END AGE ENCRYPTED FILE-----";
const armor_columns_per_line = 64;
const armor_bytes_per_line = armor_columns_per_line / 4 * 3;

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

        pub const Error = ReaderType.Error;
        pub const NoEofError = Error || error{
            EndOfStream,
        };
        pub const Reader = io.Reader(*Self, Error, read);

        const Decoder = std.base64.standard.Decoder;

        const Self = @This();

        fn fill(self: *Self) Error!usize {
            // TOOD: if we axe the middleware buffer reader we won't
            // be able to use readUntilDelimiterOrEof and should probably
            // move to a streamUnitl anyways
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
        buf: [armor_columns_per_line]u8 = undefined,
        decoded_buf: [armor_bytes_per_line]u8 = undefined,
        end: usize = 0,

        pub const Error = WriterType.Error;
        pub const Writer = io.Writer(*Self, Error, write);

        const Encoder = std.base64.standard.Encoder;

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.end + bytes.len < self.decoded_buf.len) {
                @memcpy(self.decoded_buf[self.end..][0..bytes.len], bytes);
                self.end += bytes.len;
            } else {
                var b = bytes;
                while (self.end < self.decoded_buf.len and b.len > 0) {
                    const n = @min(self.decoded_buf.len - self.end, b.len);
                    @memcpy(self.decoded_buf[self.end..][0..n], b[0..n]);
                    self.end += n;
                    if (self.end == self.decoded_buf.len) try self.flush();
                    b = b[n..];
                }
            }
            return bytes.len;
        }

        pub fn flush(self: *Self) !void {
            const n = Encoder.calcSize(self.decoded_buf[0..self.end].len);
            _ = Encoder.encode(self.buf[0..n], self.decoded_buf[0..self.end]);
            try self.w.writeAll(self.buf[0..n]);
            _ = try self.w.write("\n");
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

test "reader" {
    const words =
        \\YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4cWM5Vno0Q1dicFdRaFJ6
        \\cXRWRlRSS1Bnc29SOHdENmtTdTBYN1RvTkhzCjVkbzZpTzh6MnEwWHhEN2dSMURV
        \\bWZCb2hXUCtzaHBrK2pZcHhsTS92ck0KLS0tICs5Y2tuQktUcEw5Snh6bTB0M0Yv
        \\K1lQb1IvUlIzTXc3ZmhTYU0yL2NJ
        ;
    var fbs = std.io.fixedBufferStream(words);
    const words_reader = fbs.reader();
    var armored_reader = ArmoredReader(@TypeOf(words_reader)){.r = words_reader };
    const reader = armored_reader.reader();
    var i: usize = 0;
    while (i < 167) {
        var buf = [_]u8{0} ** 1;
        const n = try reader.read(&buf);
        if (n == 0) break;
        std.debug.print("iter: {s}\n", .{buf[0..n]});
        i += 1;
    }
}
