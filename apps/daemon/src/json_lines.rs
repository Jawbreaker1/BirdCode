use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt;
use std::io::{self, BufRead, Read, Write};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    Decode(serde_json::Error),
    TooLarge { limit: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "stdio transport failed: {error}"),
            Self::Decode(error) => write!(formatter, "invalid JSONL frame: {error}"),
            Self::TooLarge { limit } => {
                write!(formatter, "JSONL frame exceeded the {limit}-byte limit")
            }
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::TooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A bounded, ordered JSON-lines connection over arbitrary byte streams.
///
/// Stdout is reserved for these frames by the daemon. Human diagnostics go to
/// stderr so protocol consumers never need to scrape strings.
pub struct JsonLines<R, W> {
    reader: R,
    writer: W,
    max_frame_bytes: usize,
}

impl<R, W> JsonLines<R, W>
where
    R: BufRead,
    W: Write,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self::with_limit(reader, writer, DEFAULT_MAX_FRAME_BYTES)
    }

    /// Creates a connection with an explicit per-line byte limit.
    ///
    /// # Panics
    ///
    /// Panics when `max_frame_bytes` is zero.
    pub fn with_limit(reader: R, writer: W, max_frame_bytes: usize) -> Self {
        assert!(max_frame_bytes > 0, "frame limit must be non-zero");
        Self {
            reader,
            writer,
            max_frame_bytes,
        }
    }

    /// Reads and decodes the next frame, or returns `None` at clean EOF.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failures, malformed JSON, or an oversized
    /// frame. Oversized frames are drained so the following frame is aligned.
    pub fn read<T>(&mut self) -> Result<Option<T>, FrameError>
    where
        T: DeserializeOwned,
    {
        let mut frame = Vec::new();
        let bytes_read = {
            let read_limit = u64::try_from(self.max_frame_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let mut limited = self.reader.by_ref().take(read_limit);
            limited.read_until(b'\n', &mut frame)?
        };

        if bytes_read == 0 {
            return Ok(None);
        }

        if frame.len() > self.max_frame_bytes {
            if !frame.ends_with(b"\n") {
                drain_line(&mut self.reader)?;
            }
            return Err(FrameError::TooLarge {
                limit: self.max_frame_bytes,
            });
        }

        serde_json::from_slice(&frame)
            .map(Some)
            .map_err(FrameError::Decode)
    }

    /// Encodes one value, terminates it with a newline, and flushes the writer.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or output fails.
    pub fn write<T>(&mut self, value: &T) -> Result<(), FrameError>
    where
        T: Serialize,
    {
        serde_json::to_writer(&mut self.writer, value).map_err(FrameError::Decode)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

fn drain_line(input: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |position| position + 1);
        input.consume(consumed);
        if newline.is_some() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameError, JsonLines};
    use serde::{Deserialize, Serialize};
    use std::io::{BufReader, Cursor};

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Message {
        text: String,
    }

    #[test]
    fn reads_and_writes_multilingual_frames_without_transforming_content() {
        let input = Cursor::new("{\"text\":\"Hej 世界 👋\"}\n".as_bytes().to_vec());
        let mut connection = JsonLines::new(BufReader::new(input), Vec::new());

        let message: Message = connection
            .read()
            .expect("valid frame should decode")
            .expect("frame should exist");
        assert_eq!(message.text, "Hej 世界 👋");
        connection.write(&message).expect("frame should encode");

        let (_, output) = connection.into_parts();
        let decoded: Message = serde_json::from_slice(&output).expect("output should be JSON");
        assert_eq!(decoded, message);
    }

    #[test]
    fn rejects_and_drains_oversized_frames() {
        let input = Cursor::new(b"{\"oversized\":true}\n{}\n".to_vec());
        let mut connection = JsonLines::with_limit(BufReader::new(input), Vec::new(), 8);

        assert!(matches!(
            connection.read::<Message>(),
            Err(FrameError::TooLarge { limit: 8 })
        ));

        let next = connection
            .read::<serde_json::Value>()
            .expect("the next frame should remain readable")
            .expect("the next frame should exist");
        assert_eq!(next, serde_json::json!({}));
    }

    #[test]
    fn drains_a_large_oversized_remainder_without_losing_alignment() {
        let mut input = vec![b'x'; 2 * 1024 * 1024];
        input.extend_from_slice(b"\n{}\n");
        let reader = BufReader::with_capacity(64, Cursor::new(input));
        let mut connection = JsonLines::with_limit(reader, Vec::new(), 32);

        assert!(matches!(
            connection.read::<serde_json::Value>(),
            Err(FrameError::TooLarge { limit: 32 })
        ));
        assert_eq!(
            connection
                .read::<serde_json::Value>()
                .expect("the following frame should remain readable")
                .expect("the following frame should exist"),
            serde_json::json!({})
        );
    }

    #[test]
    fn reports_end_of_stream() {
        let input = Cursor::new(Vec::<u8>::new());
        let mut connection = JsonLines::new(BufReader::new(input), Vec::new());

        assert!(
            connection
                .read::<Message>()
                .expect("EOF is valid")
                .is_none()
        );
    }
}
