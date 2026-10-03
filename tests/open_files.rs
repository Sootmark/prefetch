//! Openly licensed prefetch files of every version against two
//! independent oracles: libyal's libfwnt for every compressed file,
//! byte for byte, and Eric Zimmerman's PECmd for every field it reports.
//!
//! - `tests/fixtures/pf/`: the files as found. `ez/` is the test set of
//!   EricZimmerman/Prefetch (MIT): versions 17, 23, 26 and Windows 10's
//!   compressed 30, and a file that isn't one. `plaso/` is plaso's
//!   (Apache-2.0): 17, 23, 26, compressed 30 and Windows 11's 31.
//! - `tests/fixtures/scca/`: the compressed ones, decompressed by libfwnt
//!   (`pyfwnt.lzxpress_huffman_decompress`).
//! - `tests/oracle/PECmd_Output.csv`: PECmd on `pf/`, which only runs on
//!   Windows: `.github/workflows/oracle.yml` writes it.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Every file under `dir`, as paths relative to it.
fn files(dir: &Path, under: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, under, found);
        } else if path.file_name().is_some_and(|n| n != "LICENSE") {
            found.push(path.strip_prefix(under).unwrap().to_owned());
        }
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

/// PECmd's rows, by file under `pf/`.
fn pecmd() -> HashMap<String, HashMap<String, String>> {
    let csv = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/PECmd_Output.csv");
    let text = fs::read_to_string(csv).unwrap();
    let mut lines = text.trim_start_matches('\u{feff}').lines();
    let header = fields(lines.next().unwrap());
    lines
        .map(|line| {
            let row: HashMap<String, String> = header.iter().cloned().zip(fields(line)).collect();
            let source = row["SourceFilename"].replace('\\', "/");
            let name = source
                .split_once("tests/fixtures/pf/")
                .unwrap()
                .1
                .to_owned();
            (name, row)
        })
        .collect()
}

#[test]
fn decompression_matches_libfwnt() {
    let pf = fixtures().join("pf");
    let mut names = Vec::new();
    files(&pf, &pf, &mut names);
    let mut compressed = 0;
    for name in names {
        let file = fs::read(pf.join(&name)).unwrap();
        if !file.starts_with(b"MAM") {
            continue;
        }
        let size = u32::from_le_bytes(file[4..8].try_into().unwrap()) as usize;
        let ours = prefetch::xpress::decompress(&file[8..], size).unwrap();
        let theirs = fs::read(fixtures().join("scca").join(&name)).unwrap();
        assert!(
            ours == theirs,
            "{}: decompressed bytes differ",
            name.display()
        );
        compressed += 1;
    }
    assert_eq!(compressed, 10);
}

#[test]
fn every_field_matches_pecmd() {
    let expected = pecmd();
    assert_eq!(expected.len(), 62);
    for (name, row) in &expected {
        // The file as found (compressed or not) must parse as PECmd read
        // the decompressed copy.
        let parsed = prefetch::parse(&fs::read(fixtures().join("pf").join(name)).unwrap()).unwrap();
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

#[test]
fn a_file_that_isnt_prefetch_is_refused() {
    let file = fs::read(fixtures().join("pf/ez/Bad/notAPrefetch.pf")).unwrap();
    assert!(prefetch::parse(&file).is_err());
}
