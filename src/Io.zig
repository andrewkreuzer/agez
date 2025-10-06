const Self = @This();
const std = @import("std");
const exit = std.posix.exit;
const fs = std.fs;
const Io = std.Io;
const mem = std.mem;
const File = fs.File;
const FileReader = std.fs.File.Reader;
const FileWriter = std.fs.File.Writer;

const cli = @import("cli.zig");

input: File,
output: File,
reader: FileReader,
writer: FileWriter,
output_tty: bool,

pub const Options = struct {
    read_buffer: []u8,
    write_buffer: []u8,
};

pub fn init(input: ?[]const u8, output: ?[]const u8, options: Options) !Self {
    var in: File = if (input) |path|
        try fs.cwd().openFile(path, .{}) else std.fs.File.stdin();

    const flags: fs.File.CreateFlags = .{.truncate = true};
    var out: File = if (output) |path| 
        try fs.cwd().createFile(path, flags) else std.fs.File.stdout();

    return .{
        .input = in,
        .output = out,
        .reader = in.reader(options.read_buffer),
        .writer = out.writer(options.write_buffer),
        .output_tty = out.isTty(),
    };
}

pub fn deinit(self: *Self) void {
    self.writer.interface.flush() catch |err| {
        std.debug.print("Error flushing output: {any}\n", .{err});
    };
    self.input.close();
    self.output.close();
}

pub fn openFile(file_name: []const u8) !File {
    return try fs.cwd().openFile(file_name, .{});
}

pub fn readFirstLine(buf: []u8, file_name: []const u8) ![]u8 {
    const file = try fs.cwd().openFile(file_name, .{});
    defer file.close();
    var buf_reader = file.reader(buf);
    while (buf_reader.interface.takeDelimiterExclusive('\n')) |line| {
        if (line[0] == '#') continue;
        return line;
    } else |err| switch (err) {
        error.EndOfStream, // stream ended not on a line break
        error.StreamTooLong, // line could not fit in buffer
        error.ReadFailed, // caller can check reader implementation for diagnostics
        => |e| return e,
    }
}

pub fn read_passphrase(buf: []u8, confirm: bool) ![]u8 {
    var buf_writer = std.fs.File.stdout().writer(buf);
    const pwriter = &buf_writer.interface;

    const tty = try std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write });
    defer tty.close();

    var rtty_buf: [4096]u8 = undefined;
    const rtty = tty.reader(&rtty_buf);
    var tty_reader = rtty.interface;
    var wtty_buf: [4096]u8 = undefined;
    const wtty = tty.writer(&wtty_buf);
    var tty_writer = wtty.interface;

    var term = try std.posix.tcgetattr(tty.handle);
    const term_orig = term;

    term.lflag.ECHO = false;
    term.lflag.ECHONL = true;
    try std.posix.tcsetattr(tty.handle, std.os.linux.TCSA.NOW, term);

    _ = try tty_writer.write("Enter passphrase: ");
    _ = try tty_reader.streamDelimiter(pwriter, '\n');
    const p1 = pwriter.buffered();
    pwriter.end = 0;

    if (confirm) {
        _ = try tty_writer.write("Confirm passphrase: ");
        _ = try tty_reader.streamDelimiter(pwriter, '\n');
        const p2 = pwriter.buffered();
        if (!mem.eql(u8, p1, p2)) return error.PassphraseMismatch;
    }

    try std.posix.tcsetattr(tty.handle, std.os.linux.TCSA.NOW, term_orig);

    return p1;
}

const FileErrors = enum {
    TtyInadviseable,
    OverwriteDenied,
    EmpyFile,
    MissingIdentity,
};
