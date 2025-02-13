const builtin = @import("builtin");
const std = @import("std");
const io = std.io;
const debug = std.debug;
const mem = std.mem;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const PathType = std.fs.path.PathType;
const Allocator = std.mem.Allocator;

const Recipient = @import("recipient.zig").Recipient;

const FormatError = error{
    Unexpected,
    InvalidAscii,
    // InvalidHeader,
    // InvalidVersion,
    // UnsupportedVersion,
};

pub fn AgeFile(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,

        // TODO
        filepath: ?PathType = null,
        reader: ReaderType,

        version: ?V = null,
        recipients: ?[]Recipient = null,
        mac: ?[]u8 = null,
        header: ?[]u8 = null,
        payload: ?[]u8 = null,

        const MAX_PAYLOAD_SIZE = 1 << 24; // 2MiB
        const base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;

        const Prefix = union(enum) {
            const version_prefix = "age";
            const stanza_prefix = "-> ";
            const hmac_prefix = "---";

            version,
            stanza,
            hmac,
            end,
            unknown,

            fn match(buf: []u8) Prefix {
                if (mem.eql(u8, buf, version_prefix)) {
                    return .version;
                }
                if (mem.eql(u8, buf, stanza_prefix)) {
                    return .stanza;
                }
                if (mem.eql(u8, buf, hmac_prefix)) {
                    return .hmac;
                }
                return .unknown;
            }
        };

        /// The version of the age file.
        const V = union(enum) {
            pub const prefix = "age-encryption.org/";

            v1,
            none,

            fn fromStr(str: []u8) V {
                if (mem.eql(u8, str, prefix ++ "v1")) {
                    return .v1;
                }
                return .none;
            }

            fn eql(self: V, str: []u8) bool {
                return mem.eql(u8, str, @tagName(self));
            }
        };

        pub fn Iterator() type {
            return struct {
                const Iter = @This();

                const MAX_HEADER_SIZE = 4096;
                const MAX_LINE_SIZE = 128;

                reader: ReaderType,

                read: usize = 0,
                line: usize = 0,
                reading_header: bool = true,
                header: [MAX_HEADER_SIZE]u8 = [_]u8{0} ** MAX_HEADER_SIZE,

                buf: [MAX_LINE_SIZE]u8 = [_]u8{0} ** MAX_LINE_SIZE,

                const Line = struct {
                    prefix: Prefix = .unknown,
                    bytes: []u8,
                };

                /// Reads lines of the file,
                /// keeping track of the line number and header.
                fn next(iter: *Iter) ?Line {
                    var fbs = io.fixedBufferStream(&iter.buf);
                    var reader = iter.reader;
                    const writer = fbs.writer();
                    const max_size = iter.buf.len;

                    reader.streamUntilDelimiter(writer, '\n', max_size) catch |err| switch (err) {
                        error.EndOfStream => {
                            return .{ .prefix = .end, .bytes = fbs.getWritten(), };
                        },
                        else => unreachable,
                    };

                    const line = fbs.getWritten();

                    if (iter.reading_header) {
                        const start = iter.read;
                        const end = iter.read + line.len;

                        @memcpy(iter.header[start..end], line);

                        // add back the newline so our hmac is valid
                        iter.header[end] = '\n';
                        iter.read += 1;
                    }

                    iter.line += 1;
                    iter.read += line.len;

                    const prefix = line[0..3];
                    return .{
                        .prefix = Prefix.match(prefix),
                        .bytes = line,
                    };
                }

                /// Reads until the predicate returns false or EOF is reached.
                fn readUntilFalseOrEof(iter: *Iter, pred: fn (u8) bool) ![]u8 {
                    return iter.readUntilFalseOrEofIgnore(pred, null);
                }

                /// Reads until the predicate returns false or EOF is reached,
                /// ignoring the specified bytes.
                fn readUntilFalseOrEofIgnore(iter: *Iter, pred: fn (u8) bool, ignore: ?[]const u8) ![]u8 {
                    var fbs = io.fixedBufferStream(&iter.buf);
                    var reader = iter.reader;
                    var writer = fbs.writer();
                    outer: while (true) {
                        const byte: u8 = try reader.readByte();
                        if (byte == '\n') { iter.line += 1; }

                        if (iter.reading_header) {
                            iter.header[iter.read] = byte;
                            iter.read += 1;
                        }

                        if (!pred(byte)) return fbs.getWritten();
                        if (ignore) |i| {
                            for (i) |c| {
                                if (byte == c) { continue :outer; }
                            }
                        }

                        try writer.writeByte(byte);
                    }
                }
            };
        }

        pub fn read(self: *Self) !void {
            const Iter = Iterator();
            var iter: Iter = .{ .reader = self.reader };

            while (iter.next()) |line| {
                switch (line.prefix) {
                    .version => self.version = V.fromStr(line.bytes),
                    .stanza => {
                        var args = blk: {
                            var a = std.ArrayList([]u8).init(self.allocator);
                            const stanza = line.bytes[3..];

                            for (stanza) |c| {
                                if (!Self.isValidAscii(c)) {
                                    return error.InvalidAscii;
                                }
                            }

                            var i: usize = 0;
                            var j: usize = 0;
                            while (j < stanza.len) {
                                if (stanza[j] == ' ') {
                                    const value = try self.allocator.alloc(u8, j - i);
                                    @memcpy(value, stanza[i .. j]);
                                    try a.append(value);

                                    i = j + 1;
                                }
                                if (j == stanza.len - 1) {
                                    const value = try self.allocator.alloc(u8, j - i + 1);
                                    @memcpy(value, stanza[i .. j + 1]);
                                    try a.append(value);

                                    i = j + 1;
                                }
                                j += 1;
                            }

                            break :blk a;
                        };

                        const ignore = [_]u8{'\n'};
                        const b = try iter.readUntilFalseOrEofIgnore(
                            Self.isStanzaBody,
                            &ignore
                        );

                        const body = try self.allocator.alloc(u8, b.len);
                        @memcpy(body, b);

                        var recipients = std.ArrayList(Recipient).init(self.allocator);
                        try recipients.append(.{
                            .type = args.swapRemove(0),
                            .args = try args.toOwnedSlice(),
                            .body = body,
                        });

                        self.recipients = try recipients.toOwnedSlice();
                    },
                    .hmac => {
                        const mac_len = line.bytes.len - 4; // prefix + space
                        const mac = try self.allocator.alloc(u8, mac_len);
                        @memcpy(mac, line.bytes[4..]);
                        self.mac = mac;

                        const header_len = iter.read - line.bytes.len + 2;
                        self.header = try self.allocator.alloc(u8, header_len);
                        @memcpy(self.header.?[0..header_len], iter.header[0..header_len]);

                        iter.reading_header = false;
                    },
                    else => {
                        if (!iter.reading_header) {
                            var payload = std.ArrayList(u8).init(self.allocator);
                            try payload.appendSlice(line.bytes);

                            self.payload = try payload.toOwnedSlice();

                            return;
                        } else {
                            return error.Unexpected;
                        }
                    },
                }
            }
        }

        // The valid subset of ascii for age strings is 33-126
        // but we include 32 (space) for convenience
        fn isValidAscii(c: u8) bool {
            if (c < 32 or c > 126) {
                return false;
            }
            return true;
        }

        // TODO: validate wraps at 64 and trailing bits
        fn isStanzaBody(c: u8) bool {
            return c != '\n';
        }

        pub fn verify_hmac(self: *Self, file_key: []const u8) bool {
            const salt = [_]u8{};
            var buf_hmac_key = [_]u8{0} ** 32;
            var buf_header_hmac = [_]u8{0} ** 32;
            var buf_encode = [_]u8{0} ** 64;

            const k = hkdf.extract(&salt, file_key);
            hkdf.expand(&buf_hmac_key, "header", k);
            hmac.create(&buf_header_hmac, self.header.?, &buf_hmac_key);

            const encoder = std.base64.Base64Encoder.init(base64_alphabet, null);
            const hmac_padded_len = encoder.calcSize(self.mac.?.len);
            const encoded = encoder.encode(buf_encode[0..hmac_padded_len], &buf_header_hmac);

            return std.mem.eql(u8, self.mac.?, encoded);
        }

        pub fn deinit(self: *Self) void {
            if (self.recipients) |recipients| {
                for (recipients) |*r| { r.deinit(self.allocator); }
                self.allocator.free(recipients);
            }
            if (self.mac) |mac| {
                self.allocator.free(mac);
            }
            if (self.header) |header| {
                self.allocator.free(header);
            }
            if (self.payload) |payload| {
                self.allocator.free(payload);
            }
            self.recipients = null;
            self.mac = null;
            self.header = null;
            self.payload = null;
        }
    };
}

test "age file" {
    const t = std.testing;
    var fbs = io.fixedBufferStream(
        \\age-encryption.org/v1
        \\-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
        \\EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U
        // TODO: multi recipient is failing now
        // \\-> X25519 ajtqAvDEkVNr2B7zUOtq2mAQXDSBlNrVAuM/dKb5sT4
        // \\0evrK/HQXVsQ4YaDe+659l5OQzvAzD2ytLGHQLQiqxg
        // \\-> X25519 0qC7u6AbLxuwnM8tPFOWVtWZn/ZZe7z7gcsP5kgA0FI
        // \\T/PZg76MmVt2IaLntrxppzDnzeFDYHsHFcnTnhbRLQ8
        \\--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0
        \\
    );
    const identity = "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";
    const test_file_key = "YELLOW SUBMARINE";

    const allocator = std.testing.allocator;
    var age_file = AgeFile(@TypeOf(fbs.reader())){
        .allocator = allocator,
        .reader = fbs.reader(),
    };
    defer age_file.deinit();
    try age_file.read();

    try t.expect(age_file.version.? == .v1);
    try t.expect(age_file.recipients.?.len == 1);
    try t.expect(age_file.mac.?.len == 43);

    try t.expect(std.mem.eql(u8, age_file.recipients.?[0].type.?, "X25519"));
    try t.expect(age_file.recipients.?[0].args != null);
    try t.expect(age_file.recipients.?[0].body != null);
    try t.expect(age_file.recipients.?[0].state == .uninitialized);

    try age_file.recipients.?[0].init();
    try t.expect(age_file.recipients.?[0].state == .initialized);

    const file_key = try age_file.recipients.?[0].unwrap(allocator, identity);
    try t.expect(age_file.recipients.?[0].state == .unwrapped);
    defer allocator.free(file_key);

    try t.expectEqualSlices(u8, test_file_key, file_key);
    try t.expect(age_file.verify_hmac(file_key));
    try age_file.recipients.?[0].wrap(allocator, file_key, identity);
    defer age_file.recipients.?[0].deinit(allocator);

    try t.expect(age_file.recipients.?[0].state == .wrapped);
}

test "iterator" {
    const t = std.testing;
    var fbs = io.fixedBufferStream(
        \\age-encryption.org/v1
        \\-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc
        \\EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U
        \\--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0
    );

    var iter = AgeFile(@TypeOf(fbs.reader())).Iterator(){
        .reader = fbs.reader(),
    };

    try t.expectEqualStrings("age-encryption.org/v1", (iter.next()).?.bytes);
    try t.expectEqualStrings("-> X25519 TEiF0ypqr+bpvcqXNyCVJpL7OuwPdVwPL7KQEbFDOCc", (iter.next()).?.bytes);
    try t.expectEqualStrings("EmECAEcKN+n/Vs9SbWiV+Hu0r+E8R77DdWYyd83nw7U", (iter.next()).?.bytes);
    try t.expectEqualStrings("--- Vn+54jqiiUCE+WZcEVY3f1sqHjlu/z1LCQ/T7Xm7qI0", (iter.next()).?.bytes);
    try t.expect(iter.next().?.bytes.len == 0);
}

test "invalid" {
    const t = std.testing;
    var fbs = io.fixedBufferStream("age-encryption.org/v1\n-> \x7f\n");

    const allocator = std.testing.allocator;
    var age_file = AgeFile(@TypeOf(fbs.reader())){
        .allocator = allocator,
        .reader = fbs.reader(),
    };
    defer age_file.deinit();
    try t.expectError(error.InvalidAscii, age_file.read());
}
