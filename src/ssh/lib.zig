const std = @import("std");
const mem = std.mem;

pub const Rsa = @import("rsa.zig");
pub const Parser = @import("parser.zig");

pub const PemDecoder = struct {
    pub const header = "-----BEGIN";
    pub const footer = "-----END";
    pub const max_key_size: usize = 1 << 14; // 16KiB
    pub const max_openssh_line_length: usize = 70 + 1; // 70 bytes + newline

    buf: [max_key_size]u8 = undefined,
    end: usize = 0,

    pub fn decode(self: *PemDecoder, dest: []u8, source: []const u8) ![]u8 {
        const Decoder = std.base64.standard.Decoder;
        try self.fill(source);

        const slice = self.buf[0..self.end];
        const size = try Decoder.calcSizeForSlice(slice);
        Decoder.decode(dest[0..size], slice) catch {
            return error.InvalidSshIdentity;
        };

        return dest[0..size];
    }

    pub fn decode_no_pad(self: *PemDecoder, dest: []u8, source: []const u8) ![]u8 {
        const Decoder = std.base64.standard_no_pad.Decoder;
        try self.fill(source);

        const slice = self.buf[0..self.end];
        const size = try Decoder.calcSizeForSlice(slice);
        Decoder.decode(dest[0..size], slice) catch {
            return error.InvalidSshIdentity;
        };

        return dest[0..size];
    }

    fn fill(self: *PemDecoder, source: []const u8) !void {
        var source_fbs = std.io.fixedBufferStream(source);
        var reader = source_fbs.reader();

        var line_buf: [max_openssh_line_length]u8 = undefined;
        var line_fbs = std.io.fixedBufferStream(&line_buf);
        const line_writer = line_fbs.writer();
        while (true) {
            reader.streamUntilDelimiter(line_writer, '\n', line_buf.len) catch |err| switch (err) {
                error.EndOfStream => {},
                else => return err,
            };

            const line = line_fbs.getWritten();
            line_fbs.reset();

            if (line.len == 0) break;
            if (line.len > header.len) {
                if (mem.eql(u8, line[0..header.len], header)) {
                    //TODO: parse header for keytype
                    continue;
                }
            }
            if (line.len > footer.len) {
                if (mem.eql(u8, line[0..footer.len], footer)) {
                    break;
                }
            }

            @memcpy(self.buf[self.end..self.end+line.len], line);
            self.end += line.len;
        }
    }
};
