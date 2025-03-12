const std = @import("std");
const io = std.io;
const fs = std.fs;
const exit = std.posix.exit;
const File = std.fs.File;
const BufferedReader = std.io.BufferedReader;
const BufferedWriter = std.io.BufferedWriter;

const cli = @import("cli.zig");

input: File,
output: File,
buffered_reader: BufferedReader(4096, File.Reader),
buffered_writer: BufferedWriter(4096, File.Writer),
output_tty: bool,

pub fn init(input: ?[]const u8, output: ?[]const u8) !@This() {
    var input_file: File = undefined;
    var output_file: File = undefined;

    if (input) |path| {
        input_file = try fs.cwd().openFile(path, .{});
    } else {
        input_file = std.io.getStdIn();
    }

    if (output) |path| {
        output_file = try fs.cwd().createFile(path, .{ .truncate = true });
    } else {
        output_file = std.io.getStdOut();
    }

    return .{
        .input = input_file,
        .output = output_file,
        .buffered_reader = std.io.bufferedReader(input_file.reader()),
        .buffered_writer = std.io.bufferedWriter(output_file.writer()),
        .output_tty = output_file.isTty(),
    };
}

pub fn reader(self: *@This()) @TypeOf(self.buffered_reader.reader()) {
    return self.buffered_reader.reader();
}

pub fn writer(self: *@This()) @TypeOf(self.buffered_writer.writer()) {
    return self.buffered_writer.writer();
}

pub fn deinit(self: *@This()) void {
    self.buffered_writer.flush() catch |err| {
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
    var buf_reader = std.io.bufferedReader(file.reader());
    if (try buf_reader.reader().readUntilDelimiterOrEof(buf, '\n')) |r| {
        return r;
    } else {
        return error.EmptyFile;
    }
}

pub fn read_passphrase(buf: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const pwriter = fbs.writer();

    const tty = try std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write });
    defer tty.close();

    const rtty = tty.reader();
    const wtty = tty.writer();

    var term = try std.posix.tcgetattr(tty.handle);
    const term_orig = term;

    term.lflag.ECHO = false;
    term.lflag.ECHONL = true;
    try std.posix.tcsetattr(tty.handle, std.os.linux.TCSA.NOW, term);

    _ = try wtty.write("Enter passphrase: ");
    try rtty.streamUntilDelimiter(pwriter, '\n', buf.len);

    try std.posix.tcsetattr(tty.handle, std.os.linux.TCSA.NOW, term_orig);

    //TODO: confirm passphrase
    return fbs.getWritten();
}

const FileErrors = enum {
    TtyInadviseable,
    OverwriteDenied,
    EmpyFile,
    MissingIdentity,
};
