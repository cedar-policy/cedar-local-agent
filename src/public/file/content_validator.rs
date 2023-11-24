//! Defines the wrapper class for io file reader, it will operate the some validations such as file
//! size limit check, during the file object construction

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use std::path::Path;
use thiserror::Error;

/// The `FileReaderError` occurs when the file operation failed or not in the valid format.
#[derive(Error, Debug)]
pub enum BufferReaderError {
    /// Indicates that the file size exceeds the allowed limit default = 100MB.
    #[error("The input file is too large size limit = {0}")]
    FileTooLarge(String),

    /// Indicates that the file contains non-ASCII characters.
    #[error("The input data file contains non-ascii.")]
    NonAsciiEncoded,

    /// Represents an I/O error that occurred during file processing.
    #[error("IO Error, reason = {0}")]
    IoError(#[from] io::Error),
}

/// Represents a unit of data size, such as bytes, kilobytes, megabytes, or gigabytes.
#[derive(Debug, Clone)]
pub enum ByteUnit {
    /// A unit representing bytes.
    Byte(u64),
    /// A unit representing kilobytes (1 kilobyte = 1000 bytes).
    Kilobyte(u64),
    /// A unit representing megabytes (1 megabyte = 1,000,000 bytes).
    Megabyte(u64),
    /// A unit representing gigabytes (1 gigabyte = 1,000,000,000 bytes).
    Gigabyte(u64),
    /// A unit representing gigabytes (1 gigabyte = 1,000,000,000,000 bytes).
    Terabyte(u64),
}

/// Helper function to convert `ByteUnit` to u64
impl From<&ByteUnit> for u64 {
    fn from(value: &ByteUnit) -> Self {
        match value {
            ByteUnit::Byte(bytes) => *bytes,
            ByteUnit::Kilobyte(bytes) => bytes * 1000,
            ByteUnit::Megabyte(bytes) => bytes * 1_000_000,
            ByteUnit::Gigabyte(bytes) => bytes * 1_000_000_000,
            ByteUnit::Terabyte(bytes) => bytes * 1_000_000_000_000,
        }
    }
}

/// Implement the Display to provider human-readable bytes unit
impl Display for ByteUnit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Byte(b) => {
                write!(f, "{b} B")
            }
            Self::Kilobyte(b) => {
                write!(f, "{b} KB")
            }
            Self::Megabyte(b) => {
                write!(f, "{b} MB")
            }
            Self::Gigabyte(b) => {
                write!(f, "{b} GB")
            }
            Self::Terabyte(b) => {
                write!(f, "{b} TB")
            }
        }
    }
}

/// `FileConfig` is used to construct the File object with path and maximum file size
#[derive(Debug)]
pub struct FileConfig<P>
where
    P: AsRef<Path>,
{
    /// Maximum file size allowed
    pub max_file_size: ByteUnit,
    /// File path accepts any type that could convert a value into a reference to a Path such as,
    /// `String`, `&str`, `Path`, and `PathBuf`.
    pub path: P,
}

impl<P> FileConfig<P>
where
    P: AsRef<Path>,
{
    /// Default `FileConfig` constructor with 100MB as the maximum file size
    pub fn file(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            max_file_size: ByteUnit::Megabyte(100),
            path,
        }
    }

    /// `FileConfig` constructor takes file path and maximum file size.
    pub fn file_with_size_limit(path: P, max_file_size: ByteUnit) -> Self
    where
        P: AsRef<Path>,
    {
        Self {
            max_file_size,
            path,
        }
    }

    /// Helper function to validate the file size
    ///
    /// # Errors
    ///
    /// This function can error if the file size is too large
    pub fn validation_file_size(&self) -> Result<(), BufferReaderError> {
        let file_size = std::fs::metadata(&self.path)?.len();
        if file_size > u64::from(&self.max_file_size) {
            return Err(BufferReaderError::FileTooLarge(
                self.max_file_size.to_string(),
            ));
        }
        Ok(())
    }
}

/// `FileReader` is wrapper class which will perform some validations such as file size, file
/// encoding, etc. If the file is valid, it will construct it with the `BufReader`.
#[derive(Debug)]
pub struct BufferReader {
    /// Buffer reader
    pub reader: BufReader<File>,
}

impl BufferReader {
    /// Examine the file content line by line, and if all lines are valid, return the string.
    ///
    /// # Errors
    ///
    /// This function can error if the file content is not ascii encoded.
    pub fn read_to_string(self) -> Result<String, BufferReaderError> {
        let mut buf_reader = self.reader;
        let mut line = String::new();
        while buf_reader.read_line(&mut line)? > 0 {
            if !line.is_ascii() {
                return Err(BufferReaderError::NonAsciiEncoded);
            }
        }
        Ok(line)
    }

    /// Return the `BufReader`
    ///
    /// # Errors
    ///
    /// This function can error if the file size is too large
    pub fn open<P>(file: &FileConfig<P>) -> Result<Self, BufferReaderError>
    where
        P: AsRef<Path>,
    {
        file.validation_file_size()?;

        let io_file = File::open(&file.path)?;
        Ok(Self {
            reader: BufReader::new(io_file),
        })
    }
}
#[cfg(test)]
mod tests {
    use crate::public::file::content_validator::BufferReaderError::{
        FileTooLarge, NonAsciiEncoded,
    };
    use crate::public::file::content_validator::{BufferReader, ByteUnit, FileConfig};
    use std::fs;
    use std::io::{BufRead, Write};
    use tempfile::NamedTempFile;

    #[test]
    fn file_open_is_ok() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();
        let string_data = "This is the testing string with len 38";
        temp_file.write_all(string_data.as_bytes()).unwrap();
        let f = FileConfig::file(temp_file_path);
        let reader = BufferReader::open(&f);
        assert!(reader.is_ok());
        let mut reader = reader.unwrap();
        let mut line = String::new();
        let len = reader.reader.read_line(&mut line).unwrap();
        assert_eq!(len, 38);
    }

    #[test]
    fn file_open_is_too_large() {
        let f = FileConfig::file_with_size_limit(
            "tests/data/too_many_entities.json",
            ByteUnit::Kilobyte(1),
        );
        let reader = BufferReader::open(&f);
        assert!(reader.is_err());
        assert!(matches!(reader.unwrap_err(), FileTooLarge(_)));
    }

    #[test]
    fn file_open_and_to_string_is_ok() {
        let f = FileConfig::file("tests/data/sweets.cedar");
        let reader = BufferReader::open(&f);
        assert!(reader.is_ok());
        let expect = reader.unwrap().read_to_string().unwrap();
        let actual = fs::read_to_string("tests/data/sweets.cedar").unwrap();
        assert_eq!(expect, actual);
    }

    #[test]
    fn file_open_and_to_string_is_non_ascii_encoding() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();
        let string_data = "#♠♣♥♦#";
        temp_file.write_all(string_data.as_bytes()).unwrap();
        let f = FileConfig::file(temp_file_path);
        let reader = BufferReader::open(&f);
        assert!(reader.is_ok());
        let reader = reader.unwrap().read_to_string();
        assert!(matches!(reader.unwrap_err(), NonAsciiEncoded));
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn byte_unit_conversion_display_is_ok() {
        let ten_b = u64::from(&ByteUnit::Byte(10));
        assert_eq!(ten_b, 10);
        assert_eq!(ByteUnit::Byte(10).to_string(), "10 B");

        let ten_kb = u64::from(&ByteUnit::Kilobyte(10));
        assert_eq!(ten_kb, 10000);
        assert_eq!(ByteUnit::Kilobyte(10).to_string(), "10 KB");

        let ten_mb = u64::from(&ByteUnit::Megabyte(10));
        assert_eq!(ten_mb, 10_000_000);
        assert_eq!(ByteUnit::Megabyte(10).to_string(), "10 MB");

        let ten_gb = u64::from(&ByteUnit::Gigabyte(10));
        assert_eq!(ten_gb, 10_000_000_000);
        assert_eq!(ByteUnit::Gigabyte(10).to_string(), "10 GB");

        let ten_tb = u64::from(&ByteUnit::Terabyte(10));
        assert_eq!(ten_tb, 10_000_000_000_000);
        assert_eq!(ByteUnit::Terabyte(10).to_string(), "10 TB");
    }
}
