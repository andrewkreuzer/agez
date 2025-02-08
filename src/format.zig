const std = @import("std");
const File = std.fs.File;
const Allocator = std.mem.Allocator;

const version_line = "age-encryption.org/v1";
const stanza_prefix = "-> ";
const hmac_prefix = "---";

pub const Arg = struct {
    value: [64]u8,
};

pub fn toArgs(v: []const u8) []Arg {
    var value: [64]u8 = undefined;
    @memcpy(value[0..43], v);
    var args =  [_]Arg{.{
        .value = value,
    }};

    return &args;
}

pub const Recipient = struct {
    tag: [64] u8,
    args: []Arg,
    body: []u8,
};

const MAX_HEADER_SIZE = 512;

pub const FileData = struct {
    header_len: usize,
    header_bytes: [MAX_HEADER_SIZE]u8,
    header: []u8,
    recipients: []Recipient,
    mac: [50]u8,
    mac_len: usize,
    payload: []u8,
};

// TODO: buffered reader
// fn fromFile(allocator: *Allocator, file: File) !FileData {
//     const buf_reader = std.io.bufferedReader(file.reader());
//     const reader = buf_reader.reader();
//     return try fromFile(file);
// }

pub fn fromFile(allocator: Allocator, file: File) !FileData {
    var buf: [128]u8 = undefined;
    const prefix = buf[0..3];

   var line: []u8 = try readLine(file, &buf);
    while (!std.mem.eql(u8, line, version_line)) {
        line = readLine(file, &buf) catch |err| switch (err) {
            FormatError.EndOfFile => return error.VersionNotFound,
            else => return FormatError.Unexpected,
        };
    }

    const header_start = try file.getPos() - line.len - 1;
    var header_end: usize = 0;
    var header_len: usize = 0;

    var mac: [50]u8 = [_]u8{0} ** 50;
    var mac_len: usize = 0;
    var recipients = std.ArrayList(Recipient).init(allocator);
    while (true) {
        const read = try file.read(prefix);
        if (read == 0) { break; }
        if (std.mem.eql(u8, prefix, stanza_prefix)) {
            try recipients.append(try parseStanza(allocator, file, &buf));
        }
        if (std.mem.eql(u8, prefix, hmac_prefix)) {
            header_end = try file.getPos();
            header_len = header_end - header_start;
            const mac_line = try readLine(file, &buf);
            mac_len = mac_line.len - 1; // remove space after mac prefix
            @memcpy(mac[0..mac_len], mac_line[1..]);
            break;
        }
    }

    const payload = try file.readToEndAlloc(allocator, 1 << 24);

    try file.seekTo(header_start);
    var header_bytes = [_:0]u8{0} ** MAX_HEADER_SIZE;
    _ = try file.read(header_bytes[0..header_len]);

    return .{
        .header_len = header_len,
        .header_bytes = header_bytes,
        .header = header_bytes[0..header_len],
        .recipients = try recipients.toOwnedSlice(),
        .mac_len = mac_len,
        .mac = mac,
        .payload = payload,
    };
}

fn parseStanza(allocator: Allocator, file: File, buffer: []u8) !Recipient {
    var args = std.ArrayList(Arg).init(allocator);
    var body = std.ArrayList(u8).init(allocator);
    while (true) {
        const line = try readLine(file, buffer);
        var i: usize = 0;
        for (0..line.len) |j| {
            // TAG
            if (line[j] == ' ') {
                var value = [_:0]u8{0} ** 64;
                std.mem.copyForwards(u8, &value, line[i..j]);
                try args.append(.{ .value = value});
                i = j+1;
            }
            // ARG
            if (j == line.len - 1 and line.len == 50) {
                var value = [_:0]u8{0} ** 64;
                std.mem.copyForwards(u8, &value, line[i..j+1]);
                try args.append(.{ .value = value});
                i = j+1;
            }
        }

        try body.appendSlice(line[i..]);

        // stanza's seem to wrap at 54 not 64 as the documenation says
        // we pop off stanza prefix and newline so len ends up being 50
        if (line.len < 49) {
            // remove the tag
            const tag = args.swapRemove(0);
            return .{
                .tag = tag.value,
                .args = try args.toOwnedSlice(),
                .body = try body.toOwnedSlice(),
            };
        }
    }
    return error.Unexpected;
}

fn readLine(file: File, buffer: []u8) ![]u8 {
    var i: usize = 0;
    while (true) {
        const read = try file.read(buffer[i .. i + 1]);
        if (read == 0) { return FormatError.EndOfFile; }

        if (buffer[i] == '\n') {
            return buffer[0..i];
        }

        i += 1;

        if (i == buffer.len) {
            return error.OutOfMemory;
        }
    }
}

const FormatError = error{
    Unexpected,
    EndOfFile,
    VersionNotFound,
};
