const builtin = @import("builtin");
const std = @import("std");
const exit = std.os.linux.exit;
const mem = std.mem;
const process = std.process;
const ArgIterator = process.ArgIterator;
const ArgIteratorGeneral = process.ArgIteratorGeneral;
const Allocator = std.mem.Allocator;

const Arg = struct {
    type: ?ArgType = null,
    short: ?[]const u8 = null,
    long: ?[]const u8 = null,
    value: ?[]const u8 = null,
    flag: bool = false,
    description: ?[]const u8 = null,

    const ArgType = enum {
        flag,
        value,
        multivalue,
        positional,
    };

    fn init(short: []const u8, long: []const u8, description: []const u8, argtype: ArgType) Arg {
        comptime {
            return .{
                .short = short,
                .long = long,
                .type = argtype,
                .description = description,
            };
        }
    }

    fn eql(self: Arg, arg: []const u8) bool {
        if (self.short == null or self.long == null) return false;
        return mem.eql(u8, arg, self.short.?) or mem.eql(u8, arg, self.long.?);
    }
};

const ArgError = error{
    InvalidArgument,
    EncryptAndDecrypt,
};

pub fn args(allocator: Allocator) !Args {
    var iter = try ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();
    _ = iter.skip(); // skip the program name

    var a: Args =  .{ .allocator = allocator };
    a.parse(&iter) catch |err| switch (err) {
        error.InvalidArgument => exit(1),
        error.EncryptAndDecrypt => {
            std.debug.print("Incompatible arguments: --encrypt and --decrypt\n", .{});
            exit(1);
        },
        else => return err
    };
    return a;
}

pub const Args = struct {
    const Self = @This();

    help: Arg = Arg.init("-h", "--help", "Prints the help text", .flag),
    encrypt: Arg = Arg.init("-e", "--encrypt", "Encrypt the input (default)", .flag),
    decrypt: Arg = Arg.init("-d", "--decrypt", "Decrypt the input", .flag),
    output: Arg = Arg.init("-o", "--output", "Output to a path OUTPUT", .value),
    armor: Arg = Arg.init("-a", "--armor", "Encrypt to a PEM encoded format", .flag),
    passphrase: Arg = Arg.init("-p", "--passphrase", "Encrypt with a passphrase", .value),
    // TODO: repeats
    recipient: Arg = Arg.init("-r", "--recipient", "Encrypt to a specified RECIPIENT. Can be repeated", .multivalue),
    @"recipients-file": Arg = Arg.init("-R", "--recipients-file", "Encrypt to recipients listed at PATH. Can be repeated", .multivalue),
    identity: Arg = Arg.init("-i", "--identity", "Use the identity file at PATH. Can be repeated", .multivalue),
    input: Arg = Arg.init("", "", "", .positional),

    allocator: ?Allocator = null,

    pub fn parse(self: *Self, iter: anytype) anyerror!void {
        var empty = true;
        while (iter.next()) |arg| {
            empty = false;
            if (self.help.eql(arg)) {
                self.help.flag = true;

            } else if (self.encrypt.eql(arg)) {
                if (self.decrypt.flag) return error.EncryptAndDecrypt;
                self.encrypt.flag = true;

            } else if (self.decrypt.eql(arg)) {
                if (self.encrypt.flag) return error.EncryptAndDecrypt;
                self.decrypt.flag = true;

            // TODO: don't assume next is okay to grab
            } else if (self.output.eql(arg)) {
                self.output.value = iter.next();

            } else if (self.armor.eql(arg)) {
                self.armor.flag = true;

            } else if (self.passphrase.eql(arg)) {
                self.passphrase.value = iter.next();
            } else if (self.recipient.eql(arg)) {
                self.recipient.value = iter.next();
            } else if (self.@"recipients-file".eql(arg)) {
                self.@"recipients-file".value = iter.next();
            } else if (self.identity.eql(arg)) {
                self.identity.value = iter.next();
            } else if (arg.len > 0) {
                self.input.value = arg;
            } else {
                std.debug.print("Invalid argument {s}\n", .{arg});
                return error.InvalidArgument;
            }
        }

        if (empty or self.help.flag) {
            try self.printHelp(self.allocator.?);
            exit(0);
        }
    }

    pub fn printHelp(_: *Self, allocator: Allocator) !void {
        const fields = @typeInfo(Self).Struct.fields;
        const stdout = std.io.getStdOut().writer();
        var options = try std.ArrayList(u8).initCapacity(allocator, fields.len);

        // this is completely unnecessary, but I wanted to try it out
        // TODO: figure out the spacing for descriptions
        const writer = options.writer();
        inline for (fields) |field| {
            if (field.default_value) |default| {
                if (field.type != Arg) { continue; }
                const arg = @as(*const field.type, @ptrCast(@alignCast(default))).*;
                if (arg.type == .positional) { continue; }
                try std.fmt.format(writer, "    {s}, {s}    {s}\n", .{arg.short.?, arg.long.?, arg.description.?});
            }
        }

        const header_text =
            \\agez - age encryption
            \\
            \\ Usage:
            \\    agez [--encrypt] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]
            \\    agez [--encrypt] --passphrase [--armor] [-o OUTPUT] [INPUT]
            \\    agez --decrypt [-i PATH]... [-o OUTPUT] [INPUT]
            ;
        const options_text = try options.toOwnedSlice();
        defer allocator.free(options_text);

        try std.fmt.format(stdout, 
            \\{s}
            \\
            \\Options:
            \\{s}
            , .{header_text, options_text});
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

test "single argument" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    const cases = [_]struct{
        args: []const u8,
        expected: Args,
    }{
        .{ .args = "--encrypt", .expected = .{
            .encrypt = .{ .flag = true, },
        }},
        .{ .args = "--decrypt", .expected = .{
            .decrypt = .{ .flag = true, },
        }},
        .{ .args = "--decrypt -i f", .expected = .{
            .decrypt = .{ .flag = true, },
            .identity = .{ .value = "f", },
        }},
    };

    for (cases) |c| {
        var iter = try std.process.ArgIteratorGeneral(.{}).init( allocator, c.args,);
        defer iter.deinit();

        var testing_args = Args{ .allocator = allocator };
        defer testing_args.deinit();

        try testing_args.parse(&iter);
        try t.expect(testing_args.encrypt.flag == c.expected.encrypt.flag);
        try t.expect(testing_args.decrypt.flag == c.expected.decrypt.flag);
        if (c.expected.output.value) |v|{
            try t.expect(std.mem.eql(u8, testing_args.output.value.?, v));
        }
        try t.expect(testing_args.armor.flag == c.expected.armor.flag);
        if (c.expected.passphrase.value) |v|{
            try t.expect(std.mem.eql(u8, testing_args.passphrase.value.?, v));
        }
        if (c.expected.recipient.value) |v|{
            try t.expect(std.mem.eql(u8, testing_args.recipient.value.?, v));
        }
        if (c.expected.@"recipients-file".value) |v|{
            try t.expect(std.mem.eql(u8, testing_args.@"recipients-file".value.?, v));
        }
        if (c.expected.identity.value) |v|{
            try t.expect(std.mem.eql(u8, testing_args.identity.value.?, v));
        }
    }
}

test "error" {
    const t = std.testing;
    const allocator = std.testing.allocator;

    const cases = [_]struct{
        args: []const u8,
        expected: anyerror,
    }{
        .{ .args = "--encrypt -d", .expected = error.EncryptAndDecrypt },
    };

    for (cases) |c| {
        var iter = try std.process.ArgIteratorGeneral(.{}).init( allocator, c.args,);
        defer iter.deinit();

        var testing_args = Args{ .allocator = allocator };
        defer testing_args.deinit();

        try t.expectError(error.EncryptAndDecrypt, testing_args.parse(&iter));
    }
}
