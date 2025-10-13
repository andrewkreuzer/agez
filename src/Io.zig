const Self = @This();
const std = @import("std");
const exit = std.posix.exit;
const fs = std.fs;
const Io = std.Io;
const linux = std.os.linux;
const mem = std.mem;
const posix = std.posix;
const File = fs.File;
const FileReader = std.fs.File.Reader;
const FileWriter = std.fs.File.Writer;

input: File,
output: File,
reader: FileReader,
writer: FileWriter,
output_tty: bool,

pub const Options = struct {
    input: ?[]const u8,
    output: ?[]const u8,
    read_buffer: []u8,
    write_buffer: []u8,
};

pub fn init(options: Options) !Self {
    var in: File = if (options.input) |path|
        try fs.cwd().openFile(path, .{}) else .stdin();

    const flags: fs.File.CreateFlags = .{.truncate = true};
    var out: File = if (options.output) |path|
        try fs.cwd().createFile(path, flags) else .stdout();

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

pub fn readFirstLine(buf: []u8, file_name: []const u8) ![]u8 {
    const file = try fs.cwd().openFile(file_name, .{});
    defer file.close();

    var reader = file.reader(buf);
    while (reader.interface.takeDelimiterExclusive('\n')) |line| {
        if (line[0] == '#') continue;
        return line;
    } else |err| switch (err) {
        error.EndOfStream,
        error.StreamTooLong,
        error.ReadFailed,
        => |e| return e,
    }
}

pub fn read_passphrase(buf: []u8, confirm: bool) ![]u8 {
    const base_prompt = "Enter passphrase: ";
    const confirm_prompt = "Confirm passphrase: ";

    var writer: Io.Writer = .fixed(buf);

    const tty = try std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write });
    defer tty.close();

    var tty_buf: [128]u8 = undefined;
    var tty_in = tty.reader(&tty_buf);
    var tty_out = tty.writer(&.{});
    var tty_reader = &tty_in.interface;
    var tty_writer = &tty_out.interface;

    var term = try posix.tcgetattr(tty.handle);
    const term_orig = term;

    // Disable output to hide password input but
    // keep nl to show enter was received
    term.lflag.ECHO = false;
    term.lflag.ECHONL = true;
    try posix.tcsetattr(tty.handle, linux.TCSA.NOW, term);


    var n: usize = 0;
    for (0..2) |i| {
        const prompt = if (i == 0) base_prompt else confirm_prompt;
        try tty_writer.writeAll(prompt);
        n = try tty_reader.streamDelimiter(&writer, '\n');
        if (!confirm) break;
        tty_reader.toss(1);
    }
    const p1 = buf[0..n];
    const p2 = buf[n..][0..n];
    if (confirm and !mem.eql(u8, p1, p2))
        return error.PassphraseMismatch;

    try std.posix.tcsetattr(tty.handle, linux.TCSA.NOW, term_orig);

    return p1;
}

const FileErrors = enum {
    TtyInadviseable,
    OverwriteDenied,
    EmpyFile,
    MissingIdentity,
};
