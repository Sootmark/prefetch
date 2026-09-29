# prefetch

A Windows Prefetch (`.pf`) parser, written from the public format documentation: versions 17 (XP/2003), 23 (Vista/7), 26 (8.1) and 30/31 (Windows 10/11), including the compressed form Windows 8 and later write, with its own LZ77+Huffman ([MS-XCA]) decompressor. No dependencies.

```toml
[dependencies]
sootmark-prefetch = "0.1"
```

```rust
let prefetch = prefetch::parse(&std::fs::read("CMD.EXE-087B4001.pf")?)?;
println!("{} ran {} times", prefetch.executable, prefetch.run_count);
for time in &prefetch.last_runs {
    println!("  at FILETIME {time}");
}
for volume in &prefetch.volumes {
    println!("  {} (serial {:08X})", volume.device_path, volume.serial);
}
```

## What you get

- `parse(bytes)`: compressed (`MAM`) or not. The executable name, prefetch hash, run count and last run times (one before version 26, up to eight since), as FILETIMEs.
- `files`: the files loaded in the program's first seconds, with their NTFS file references (version 23 and later).
- `volumes`: device path, serial number, creation time, and the directories touched.
- `problems`: a damaged file or volume table is reported there and the rest kept; only a damaged header or compressed stream refuses the file.
- `xpress::decompress`: the LZ77+Huffman decompressor on its own.

## How it's checked

- Real files of every version (17, 23, 26, both layouts of 30, compressed and not) against Eric Zimmerman's PECmd on every field it reports, and the decompressor against an independent implementation, byte for byte. The files aren't redistributable: the test runs when they're in `tests/fixtures-real/` and says so when they aren't.
- Files built byte by byte for every version and layout; a round-trip property test through an encoder written from MS-XCA; no panic on garbage, truncated or corrupted input (property tests).

## Licence

MIT or Apache-2.0, at your option.

[MS-XCA]: https://learn.microsoft.com/openspecs/windows_protocols/ms-xca
