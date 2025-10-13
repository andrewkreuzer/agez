# agez

A zig implementation of the age encryption protocol. Supports file encryption
and decryption for multiple recipient types including X25519 age keys, openSSH
RSA and Ed25519 keys, and passphrases (scrypt), armored output with base64
encoding for text based transmission, and exposes a public api for use in zig
projects.

## Usage

### Generating Keys

Generate a new age key pair.

```sh
agez-keygen -o key.txt
```

Convert an identity file to a recipients file.

```sh
agez-keygen --convert key.txt
```

### Encrypting Files

Encrypt a file to a recipient. You can specify the recipient directly using
their public key.

```sh
agez -r age1vuvnpgd2vf70gjmn3rl0zmwz2fsrhjm66r3zl2gtkal9q0yjp4gsscrzmv -o output.age input.txt
```

Encrypt to multiple recipients. The file can be decrypted by any of the
specified recipients.

```sh
agez -r age1vuvnpgd2vf70gjmn3rl0zmwz2fsrhjm66r3zl2gtkal9q0yjp4gsscrzmv \
     -r age1xsqc3v0lc5ezdehst4xyv4slkcu7kjz3y3jkrdlnzxadqdmt0evqg80cv6 \
     -o output.age input.txt
```

Encrypt using a recipients file. Create a file with one recipient per line and
reference it with the `-R` flag.

```sh
agez -R recipients.txt -o output.age input.txt
```

Encrypt with armor mode to produce ASCII-armored output suitable for copying and
pasting.

```sh
agez --armor -r age1vuvnpgd2vf70gjmn3rl0zmwz2fsrhjm66r3zl2gtkal9q0yjp4gsscrzmv -o output.txt input.txt
```

Encrypt with a passphrase (scrypt) instead of using a public key.

```sh
agez --passphrase -o output.age input.txt
```

Encrypt using an SSH public key as the recipient.

```sh
agez -R ~/.ssh/id_rsa.pub -o output.age input.txt
```

Encrypt from stdin to stdout for use in pipelines.

```sh
echo "secret data" | agez -r age1vuvnpgd2vf70gjmn3rl0zmwz2fsrhjm66r3zl2gtkal9q0yjp4gsscrzmv > output.age
```

### Decrypting Files

Decrypt using your identity file.

```sh
agez --decrypt -i key.txt -o output.txt input.age
```

Decrypt with a passphrase.

```sh
agez --decrypt --passphrase -o output.txt input.age
```

Decrypt using an SSH private key as the identity.

```sh
agez --decrypt -i ~/.ssh/id_rsa -o output.txt input.age
```

Decrypt from stdin to stdout for use in pipelines.

```sh
cat input.age | agez --decrypt -i key.txt > output.txt
```

## Library Usage

### Add dependency

Add to your build.zig.zon
```zig
.{
    .name = "project-name",
    .version = "0.0.0",
    .dependencies = .{
        .agez = .{
            .url = "https://github.com/andrewkreuzer/agez/archive/<git-ref>.tar.gz",
            .hash = "",
        },
    },
}
```

Leave the hash empty and `zig build` will error, printing the expected hash for
the provided commit.

Add the library to your build.zig
```zig
const agez = b.dependency("agez", .{ .target = target, .optimize = optimize });
exe.addImport("agez", agez.module("agez"));
```

### Basic usage

```zig
const agez = @import("agez");

// generate your own file key
const file_key: agez.Key = try Key.init(allocator, 16);
// securely zero's the memory on slice key types
defer file_key.deinit(allocator);

// encryption
const encryptor: agez.AgeEncryptor = .init(allocator, reader, writer);
try encryptor.encrypt(&file_key, recipients, armored);

// decryption
const decryptor: agez.AgeDecryptor = .init(allocator, reader, writer);
try decryptor.decrypt(identities.?);
```

### Use the ChaChaPoly cipher directly
```zig
// encryption a payload
try agez.age.encrypt(&file_key, &reader, &writer);

// decrypt a payload
var age_reader: AgeReader = .init(
    allocator, &reader, &.{}
);
try agez.age.decrypt(&file_key, &age_reader, &writer);
```

### Reading an age header
```zig
// Only care about the recipients in the header?
var armored_buffer: [128]u8 = undefined;
var age_reader: AgeReader = .init(
    allocator, &reader, &armored_buffer
);

var header = try age_reader.parse();
defer header.deinit(allocator);
for (header.recipients.items) |r| {
    std.debug.print("recipient type: {s}\n", .{@tagName(r.type)});
}

// or getting the file key
const file_key: Key = try header.unwrap(allocator, identities);
defer file_key.deinit(allocator);
```

## Build

Build the project using Zig's build system. Run `zig build` to compile both
executables, which will be available in `zig-out/bin/`. To run tests, use `zig
build test` the age [testkit](https://github.com/C2SP/CCTV/tree/main/age) can be
run using `zig build testkit`

