const std = @import("std");
const fs = std.fs;
const exit = std.posix.exit;
const File = std.fs.File;
const BufferedReader = std.io.BufferedReader;
const BufferedWriter = std.io.BufferedWriter;
const GenericReader = std.io.GenericReader;
const GenericWriter = std.io.GenericWriter;

const cli = @import("cli.zig");

input: File,
output: File,
buffered_reader: BufferedReader(4096, File.Reader),
buffered_writer: BufferedWriter(4096, File.Writer),

pub fn init(args: cli.Args) !@This() {
    var input_file: File = undefined;
    var output_file: File = undefined;

    if (args.input.value) |path| {
        input_file = try fs.cwd().openFile(path, .{});
    } else {
        input_file = std.io.getStdIn();
    }

    if (args.output.value) |path| {
        output_file = try fs.cwd().createFile(path, .{ .truncate = true });
    } else {
        output_file = std.io.getStdOut();
        if (input_file.isTty()) {
            std.debug.print(
                \\Output is a tty, it's not recommended to write arbitrary data to the terminal
                \\use -o, --output to specify a file or redirect stdout
                \\
                , .{}
            );
            exit(1);
        }
    }

    return .{
        .input = input_file,
        .output = output_file,
        .buffered_reader = std.io.bufferedReader(input_file.reader()),
        .buffered_writer = std.io.bufferedWriter(output_file.writer()),
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

pub fn identity(buf: []u8, args: cli.Args) ![]u8 {
    if (args.identity.value) |identity_file| {
        const file = try fs.cwd().openFile(identity_file, .{});
        var buf_reader = std.io.bufferedReader(file.reader());
        if (try buf_reader.reader().readUntilDelimiterOrEof(buf, '\n')) |r| {
            return r;
        } else {
            return error.EmptyIdentityFile;
        }
    }
    return error.MissingIdentity;
}

const FileErrors = enum {
    TtyInadviseable,
    OverwriteDenied,
    EmpyIdentityFile,
};
