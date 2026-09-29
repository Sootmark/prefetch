//! LZ77+Huffman ("Xpress Huffman") decompression, from Microsoft's
//! [MS-XCA] §2.2.4: what Windows 8 and later compress prefetch files with.
//!
//! The input is a series of blocks, each producing up to 65,536 bytes: a
//! 256-byte table of 512 four-bit code lengths, then a bit stream of
//! canonical Huffman codes read as 16-bit little-endian words. Symbols
//! below 256 are literals; the others encode a match's length (low four
//! bits, extended by the following bytes) and the bit length of its
//! offset.
//!
//! [MS-XCA]: https://learn.microsoft.com/openspecs/windows_protocols/ms-xca

use core::fmt;

/// Output bytes per block.
const BLOCK: usize = 65_536;
/// The longest code.
const MAX_BITS: u32 = 15;
const SYMBOLS: usize = 512;

/// Why decompression stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ended mid-block.
    Truncated,
    /// A block's code lengths don't form a usable code.
    BadTable,
    /// A match refers to bytes before the start of the output.
    BadOffset,
    /// A match's extended length is out of range.
    BadLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "compressed data ends mid-block",
            Self::BadTable => "invalid Huffman table",
            Self::BadOffset => "match before the start of the output",
            Self::BadLength => "invalid match length",
        })
    }
}

impl std::error::Error for Error {}

/// A block's decoding table: for each 15-bit prefix, the symbol and its
/// code length.
struct Table {
    entries: Vec<(u16, u8)>,
}

impl Table {
    fn new(lengths: &[u8; SYMBOLS]) -> Result<Self, Error> {
        let mut entries = vec![(0_u16, 0_u8); 1 << MAX_BITS];
        let mut code: u32 = 0;
        let mut filled = 0_usize;
        for bits in 1..=MAX_BITS {
            for (symbol, &length) in lengths.iter().enumerate() {
                if u32::from(length) != bits {
                    continue;
                }
                let span = 1_usize << (MAX_BITS - bits);
                let start = (code as usize) << (MAX_BITS - bits);
                let end = start + span;
                if end > entries.len() {
                    return Err(Error::BadTable);
                }
                entries[start..end].fill((symbol as u16, length));
                filled += span;
                code += 1;
            }
            code <<= 1;
        }
        // An incomplete code leaves prefixes no symbol owns; those only
        // matter if the stream uses them, which `decode` rejects.
        if filled == 0 {
            return Err(Error::BadTable);
        }
        Ok(Self { entries })
    }
}

/// Reads the bit stream: 16-bit little-endian words, most significant bit
/// first, with 32 bits buffered.
struct Bits<'a> {
    input: &'a [u8],
    at: usize,
    next: u32,
    extra: i32,
}

impl<'a> Bits<'a> {
    fn new(input: &'a [u8], at: usize) -> Result<Self, Error> {
        let mut bits = Self {
            input,
            at,
            next: 0,
            extra: 16,
        };
        bits.next = (u32::from(bits.word()?) << 16) | u32::from(bits.word()?);
        Ok(bits)
    }

    fn word(&mut self) -> Result<u16, Error> {
        let bytes = self
            .input
            .get(self.at..self.at + 2)
            .ok_or(Error::Truncated)?;
        self.at += 2;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self.input.get(self.at).ok_or(Error::Truncated)?;
        self.at += 1;
        Ok(byte)
    }

    /// Drop `count` bits, refilling from the input.
    fn consume(&mut self, count: u32) -> Result<(), Error> {
        if count == 0 {
            return Ok(());
        }
        self.next = self.next.checked_shl(count).unwrap_or(0);
        self.extra -= count as i32;
        if self.extra < 0 {
            self.next |= u32::from(self.word()?) << (-self.extra) as u32;
            self.extra += 16;
        }
        Ok(())
    }
}

/// Decompress `input` into `size` bytes.
///
/// # Errors
/// When the input is truncated or malformed.
pub fn decompress(input: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(size);
    let mut at = 0;
    while output.len() < size {
        let table_bytes = input.get(at..at + SYMBOLS / 2).ok_or(Error::Truncated)?;
        let mut lengths = [0_u8; SYMBOLS];
        for (i, byte) in table_bytes.iter().enumerate() {
            lengths[2 * i] = byte & 0x0f;
            lengths[2 * i + 1] = byte >> 4;
        }
        let table = Table::new(&lengths)?;
        let mut bits = Bits::new(input, at + SYMBOLS / 2)?;
        let end = (output.len() + BLOCK).min(size);
        while output.len() < end {
            let (symbol, length) = table.entries[(bits.next >> (32 - MAX_BITS)) as usize];
            if length == 0 {
                return Err(Error::BadTable);
            }
            bits.consume(u32::from(length))?;
            if symbol < 256 {
                output.push(symbol as u8);
                continue;
            }
            let symbol = symbol - 256;
            let offset_bits = u32::from(symbol >> 4);
            let mut length = usize::from(symbol & 0x0f);
            if length == 15 {
                length = usize::from(bits.byte()?);
                if length == 255 {
                    length = usize::from(bits.word()?);
                    if length == 0 {
                        let low = bits.word()?;
                        let high = bits.word()?;
                        length = (usize::from(high) << 16) | usize::from(low);
                    }
                    length = length.checked_sub(15).ok_or(Error::BadLength)?;
                }
                length += 15;
            }
            length += 3;
            let offset = if offset_bits == 0 {
                1
            } else {
                ((bits.next >> (32 - offset_bits)) as usize) | (1 << offset_bits)
            };
            bits.consume(offset_bits)?;
            let from = output.len().checked_sub(offset).ok_or(Error::BadOffset)?;
            // Byte by byte: a match may overlap what it produces.
            for i in 0..length.min(size - output.len()) {
                output.push(output[from + i]);
            }
        }
        at = bits.at;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block whose code gives every literal 8 bits and all else nothing.
    fn literal_table() -> Vec<u8> {
        let mut table = vec![0x88_u8; 128];
        table.extend([0_u8; 128]);
        table
    }

    #[test]
    fn decodes_literals() {
        let mut input = literal_table();
        // With 256 codes of 8 bits, the code of byte b is b itself: the
        // stream is the text, as 16-bit little-endian words.
        for pair in b"Hi!\0".chunks(2) {
            input.extend([pair[1], pair[0]]);
        }
        input.extend([0, 0, 0, 0]);
        assert_eq!(decompress(&input, 3).unwrap(), b"Hi!");
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        assert_eq!(decompress(&[0; 10], 5), Err(Error::Truncated));
        let mut input = vec![0_u8; 256];
        input.extend([0; 8]);
        assert_eq!(decompress(&input, 5), Err(Error::BadTable));
    }
}
