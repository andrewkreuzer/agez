const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const Io = std.Io;

pub const prefix = "-----BEGIN ";
pub const suffix = "-----END ";
pub const openssh_header = "-----BEGIN OPENSSH PRIVATE KEY-----";
pub const openssh_footer = "-----END OPENSSH PRIVATE KEY-----";
pub const max_openssh_line_length: usize = 70 + 1; // 70 bytes + newline

pub fn isPemFormat(data: []const u8) bool {
    return mem.startsWith(u8, data, openssh_header) and mem.endsWith(u8, data, openssh_footer);
}

pub fn decode(dest: []u8, source: []const u8) ![]u8 {
    const Base64Decoder = std.base64.standard.Decoder;
    return decodeInner(Base64Decoder, dest, source);
}

pub fn decode_no_pad(dest: []u8, source: []const u8) ![]u8 {
    const Base64Decoder = std.base64.standard_no_pad.Decoder;
    return decodeInner(Base64Decoder, dest, source);
}

fn decodeInner(Decoder: std.base64.Base64Decoder, dest: []u8, source: []const u8) ![]u8 {
    var buf: [4096]u8 = undefined;
    var h: bool = false;
    var f: bool = false;
    var n: usize = 0;
    var r: Io.Reader = .fixed(source);
    var w: Io.Writer = .fixed(&buf);
    while (r.takeDelimiterExclusive('\n')) |line| {
        if (!h and line.len == openssh_header.len) {
            if (mem.eql(u8, line, openssh_header)) {
                h = true;
                continue;
            }
        }
        if (!f and line.len == openssh_footer.len) {
            if (mem.eql(u8, line, openssh_footer)) {
                f = true;
                continue;
            }
        }
        try w.writeAll(line);
        n += line.len;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return error.InvalidSshIdentity
    }
    const size = Decoder.calcSizeForSlice(buf[0..n]) catch {
        return error.InvalidSshIdentity;
    };
    assert(dest.len > size);
    Decoder.decode(dest, buf[0..n]) catch {
        return error.InvalidSshIdentity;
    };
    return dest[0..size];
}
