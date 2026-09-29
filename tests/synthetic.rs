//! Files built byte by byte from the format documentation, for every
//! version and layout; LZ77+Huffman round trips through a small encoder
//! written from MS-XCA; and no input makes the parser panic.

use proptest::prelude::*;

/// A prefetch file of `version` loading two files from one volume with
/// two directories; version 30's short layout when `short`.
fn build(version: u32, short: bool) -> Vec<u8> {
    let (info, metric, volume, runs_at, run_slots, count_at) = match version {
        17 => (68, 20, 40, 120, 1, 144),
        23 => (156, 32, 104, 128, 1, 152),
        26 => (224, 32, 104, 128, 8, 208),
        _ if short => (212, 32, 96, 128, 8, 200),
        _ => (220, 32, 96, 128, 8, 208),
    };
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let files = [
        r"\VOLUME{01}\WINDOWS\SYSTEM32\NTDLL.DLL",
        r"\VOLUME{01}\TOOLS\RCLONE.EXE",
    ];
    let metrics_at = 84 + info;
    let strings_at = metrics_at + files.len() * metric;
    let mut strings = Vec::new();
    let mut names = Vec::new();
    for file in files {
        names.push((strings.len(), file.encode_utf16().count()));
        strings.extend(utf16(file));
        strings.extend([0, 0]);
    }
    let volumes_at = strings_at + strings.len();
    let device = r"\VOLUME{01db8b4b23888202-5ab3c3d2}";
    let path_at = volume;
    let directories_at = path_at + 2 * (device.len() + 1);
    let mut volume_bytes = vec![0_u8; volume];
    volume_bytes[0..4].copy_from_slice(&(path_at as u32).to_le_bytes());
    volume_bytes[4..8].copy_from_slice(&(device.len() as u32).to_le_bytes());
    volume_bytes[8..16].copy_from_slice(&0x01db_8b4b_2388_8202_u64.to_le_bytes());
    volume_bytes[16..20].copy_from_slice(&0x5ab3_c3d2_u32.to_le_bytes());
    volume_bytes[28..32].copy_from_slice(&(directories_at as u32).to_le_bytes());
    volume_bytes[32..36].copy_from_slice(&2_u32.to_le_bytes());
    volume_bytes.extend(utf16(device));
    volume_bytes.extend([0, 0]);
    for directory in [r"\VOLUME{01}\WINDOWS", r"\VOLUME{01}\TOOLS"] {
        volume_bytes.extend((directory.len() as u16).to_le_bytes());
        volume_bytes.extend(utf16(directory));
        volume_bytes.extend([0, 0]);
    }

    let mut data = vec![0_u8; metrics_at];
    data[0..4].copy_from_slice(&version.to_le_bytes());
    data[4..8].copy_from_slice(b"SCCA");
    data[16..16 + 2 * 10].copy_from_slice(&utf16("RCLONE.EXE"));
    data[76..80].copy_from_slice(&0xEE41_1A20_u32.to_le_bytes());
    let put = |data: &mut Vec<u8>, at: usize, value: u32| {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(&mut data, 84, metrics_at as u32);
    put(&mut data, 88, files.len() as u32);
    put(&mut data, 100, strings_at as u32);
    put(&mut data, 104, strings.len() as u32);
    put(&mut data, 108, volumes_at as u32);
    put(&mut data, 112, 1);
    for slot in 0..run_slots {
        let time = 0x01dc_2f00_0000_0000_u64 - slot as u64 * 1_000_000_000;
        data[runs_at + 8 * slot..runs_at + 8 * slot + 8].copy_from_slice(&time.to_le_bytes());
    }
    put(&mut data, count_at, 42);
    for (i, (name_at, chars)) in names.iter().enumerate() {
        let mut entry = vec![0_u8; metric];
        let (offset_at, length_at) = if metric == 20 { (8, 12) } else { (12, 16) };
        entry[offset_at..offset_at + 4].copy_from_slice(&(*name_at as u32).to_le_bytes());
        entry[length_at..length_at + 4].copy_from_slice(&(*chars as u32).to_le_bytes());
        if metric == 32 {
            entry[24..32].copy_from_slice(&(0x0001_0000_0000_0100_u64 + i as u64).to_le_bytes());
        }
        data.extend(entry);
    }
    data.extend(strings);
    data.extend(volume_bytes);
    let size = data.len() as u32;
    data[12..16].copy_from_slice(&size.to_le_bytes());
    data
}

#[test]
fn every_version_and_layout() {
    for (version, short) in [
        (17, false),
        (23, false),
        (26, false),
        (30, false),
        (30, true),
        (31, false),
    ] {
        let parsed = prefetch::parse(&build(version, short)).unwrap();
        let label = format!("version {version}{}", if short { " (short)" } else { "" });
        assert!(parsed.problems.is_empty(), "{label}: {:?}", parsed.problems);
        assert_eq!(parsed.version, version);
        assert_eq!(parsed.executable, "RCLONE.EXE", "{label}");
        assert_eq!(parsed.hash, 0xEE41_1A20, "{label}");
        assert_eq!(parsed.run_count, 42, "{label}");
        assert_eq!(
            parsed.last_runs.len(),
            if version < 26 { 1 } else { 8 },
            "{label}"
        );
        assert_eq!(parsed.last_runs[0], 0x01dc_2f00_0000_0000, "{label}");
        assert_eq!(
            parsed.files[1].path, r"\VOLUME{01}\TOOLS\RCLONE.EXE",
            "{label}"
        );
        assert_eq!(
            parsed.files[1].file_reference,
            (version > 17).then_some(0x0001_0000_0000_0101),
            "{label}"
        );
        let volume = &parsed.volumes[0];
        assert_eq!(
            volume.device_path, r"\VOLUME{01db8b4b23888202-5ab3c3d2}",
            "{label}"
        );
        assert_eq!(volume.serial, 0x5ab3_c3d2, "{label}");
        assert_eq!(
            volume.directories,
            [r"\VOLUME{01}\WINDOWS", r"\VOLUME{01}\TOOLS"],
            "{label}"
        );
    }
}

/// Bits, most significant first, into 16-bit words.
#[derive(Default)]
struct BitWriter {
    words: Vec<u16>,
    acc: u32,
    used: u32,
}

impl BitWriter {
    fn put(&mut self, value: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((value >> i) & 1);
            self.used += 1;
            if self.used == 16 {
                self.words.push(self.acc as u16);
                (self.acc, self.used) = (0, 0);
            }
        }
    }

    /// The words, padded, then the two the decoder reads ahead.
    fn finish(mut self) -> Vec<u16> {
        if self.used > 0 {
            self.put(0, 16 - self.used);
        }
        self.words.extend([0, 0]);
        self.words
    }
}

/// An LZ77+Huffman encoder for tests, per MS-XCA: one block (at most
/// 65,536 bytes), every symbol a 9-bit code (a complete code, so symbol s
/// is code s), greedy matches of 3 to 17 bytes (no length extension).
fn compress(input: &[u8]) -> Vec<u8> {
    assert!(input.len() <= 65_536);
    let mut out = vec![0x99_u8; 256];
    let mut bits = BitWriter::default();
    let mut at = 0;
    while at < input.len() {
        let mut best = (0, 0);
        for from in at.saturating_sub(4096)..at {
            let mut length = 0;
            while length < 17
                && at + length < input.len()
                && input[from + length] == input[at + length]
            {
                length += 1;
            }
            if length > best.0 {
                best = (length, at - from);
            }
        }
        if best.0 >= 3 {
            let (length, offset) = best;
            let offset_bits = (offset as u32).ilog2();
            let symbol = 256 + ((offset_bits << 4) | (length as u32 - 3));
            bits.put(symbol, 9);
            bits.put(offset as u32 - (1 << offset_bits), offset_bits);
            at += length;
        } else {
            bits.put(u32::from(input[at]), 9);
            at += 1;
        }
    }
    for word in bits.finish() {
        out.extend(word.to_le_bytes());
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn round_trips(chunks in proptest::collection::vec((any::<u8>(), 1_usize..40), 0..400)) {
        // Runs of repeated bytes and random bytes: matches and literals.
        let input: Vec<u8> = chunks.iter().flat_map(|&(b, n)| {
            if n % 3 == 0 { vec![b; n] } else { (0..n).map(|i| b.wrapping_mul(i as u8 + 7)).collect() }
        }).take(65_536).collect();
        let packed = compress(&input);
        prop_assert_eq!(prefetch::xpress::decompress(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn never_panics_on_garbage(data in proptest::collection::vec(any::<u8>(), 0..2_000)) {
        let _ = prefetch::parse(&data);
        let mut mam = b"MAM\x04".to_vec();
        mam.extend(data);
        let _ = prefetch::parse(&mam);
    }

    #[test]
    fn never_panics_on_damaged_files(version in prop::sample::select(vec![17_u32, 23, 26, 30, 31]), flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..20), cut in any::<usize>()) {
        let mut data = build(version, false);
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        let _ = prefetch::parse(&data);
    }
}
