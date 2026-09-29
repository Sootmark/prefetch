//! Real prefetch files against two independent oracles: an independent
//! LZ77+Huffman decompressor's output for every compressed file, and
//! Eric Zimmerman's PECmd for every field it reports.
//!
//! The files aren't redistributable: put them in `tests/fixtures-real/`
//! (`pf/` as found, `scca/` decompressed by the other tool, and PECmd's
//! `PECmd_Output.csv` for `scca/`). Without them this test says so and
//! passes.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn fixtures() -> Option<&'static Path> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures-real");
    if dir.join("PECmd_Output.csv").exists() {
        Some(Box::leak(dir.into_boxed_path()))
    } else {
        eprintln!("no real prefetch fixtures in {}: skipped", dir.display());
        None
    }
}

/// FILETIME as PECmd prints it: `2013-03-10 10:11:49` (UTC, seconds).
fn pecmd_time(filetime: u64) -> String {
    let seconds = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// A CSV line split on commas outside quotes (enough for PECmd's output).
fn fields(line: &str) -> Vec<String> {
    let (mut out, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut field)),
            c => field.push(c),
        }
    }
    out.push(field);
    out
}

fn pecmd(dir: &Path) -> HashMap<String, HashMap<String, String>> {
    let text = fs::read_to_string(dir.join("PECmd_Output.csv")).unwrap();
    let mut lines = text.trim_start_matches('\u{feff}').lines();
    let header = fields(lines.next().unwrap());
    lines
        .map(|line| {
            let row: HashMap<String, String> = header.iter().cloned().zip(fields(line)).collect();
            let name = row["SourceFilename"]
                .rsplit(['/', '\\'])
                .next()
                .unwrap()
                .to_owned();
            (name, row)
        })
        .collect()
}

#[test]
fn decompression_matches_the_other_decompressor() {
    let Some(dir) = fixtures() else { return };
    let mut compressed = 0;
    for entry in fs::read_dir(dir.join("pf")).unwrap() {
        let path = entry.unwrap().path();
        let file = fs::read(&path).unwrap();
        if !file.starts_with(b"MAM") {
            continue;
        }
        let size = u32::from_le_bytes(file[4..8].try_into().unwrap()) as usize;
        let ours = prefetch::xpress::decompress(&file[8..], size).unwrap();
        let theirs = fs::read(dir.join("scca").join(path.file_name().unwrap())).unwrap();
        assert!(
            ours == theirs,
            "{}: decompressed bytes differ",
            path.display()
        );
        compressed += 1;
    }
    assert!(compressed >= 10, "only {compressed} compressed files");
}

#[test]
fn every_field_matches_pecmd() {
    let Some(dir) = fixtures() else { return };
    let expected = pecmd(dir);
    assert!(expected.len() >= 14);
    for (name, row) in &expected {
        // The file as found (compressed or not) must parse as PECmd read
        // the decompressed copy.
        let parsed = prefetch::parse(&fs::read(dir.join("pf").join(name)).unwrap()).unwrap();
        let at = |field: &str| row[field].as_str();
        assert!(parsed.problems.is_empty(), "{name}: {:?}", parsed.problems);
        assert_eq!(parsed.executable, at("ExecutableName"), "{name}");
        assert_eq!(format!("{:X}", parsed.hash), at("Hash"), "{name}");
        assert_eq!(parsed.run_count.to_string(), at("RunCount"), "{name}");
        let runs: Vec<String> = parsed.last_runs.iter().map(|&t| pecmd_time(t)).collect();
        let mut theirs = vec![at("LastRun").to_owned()];
        theirs.extend(
            (0..7)
                .map(|i| row[&format!("PreviousRun{i}")].clone())
                .filter(|t| !t.is_empty()),
        );
        assert_eq!(runs, theirs, "{name}: run times");
        for (i, volume) in parsed.volumes.iter().enumerate().take(2) {
            assert_eq!(volume.device_path, at(&format!("Volume{i}Name")), "{name}");
            assert_eq!(
                format!("{:X}", volume.serial),
                at(&format!("Volume{i}Serial")),
                "{name}"
            );
            assert_eq!(
                pecmd_time(volume.created),
                at(&format!("Volume{i}Created")),
                "{name}"
            );
        }
        let files: Vec<&str> = parsed.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(files.join(", "), at("FilesLoaded"), "{name}: files loaded");
        // PECmd joins a volume's directories with ", " but runs volumes
        // together with nothing between them (`…\CONEMU\VOLUME{…}`).
        let directories: String = parsed
            .volumes
            .iter()
            .map(|v| v.directories.join(", "))
            .collect();
        assert_eq!(directories, at("Directories"), "{name}: directories");
    }
}
