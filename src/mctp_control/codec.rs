// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

//As of DSP0235 1.3.3 Line 1823: "11.6 MCTP control message transmission unit size"
const MCTP_CONTROL_MTU: usize = 64;

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum MctpCodecError {
    BufferTooShort,
    Unsupported,
    InvalidData,
    InternalError,
    UnsupportedBufferSize,
}

/// A trait for encoding and decoding MCTP (Management Component Transport Protocol) messages.
///
/// This trait provides methods for encoding an MCTP message into a byte buffer
/// and decoding an MCTP message from a byte buffer. Implementers of this trait
/// must also implement the `Debug` trait and be `Sized`.
#[allow(dead_code)]
pub trait MctpCodec<'a>: core::fmt::Debug + Sized {
    /// Encodes the MCTP message into the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a byte slice where the encoded message will be stored.
    ///
    /// # Returns
    ///
    /// A `Result` containing the size of the encoded message on success, or an `MctpCodecError` on failure.
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError>;

    /// Decodes an MCTP message from the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A reference to a byte slice containing the encoded message.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded message on success, or an `MctpCodecError` on failure.
    fn decode(buffer: &'a [u8]) -> Result<Self, MctpCodecError>;

    /// Maximum supported size of MCTP message in bytes.
    ///
    /// Defaults to `core::mem::size_of::<Self>()` for the implementing type.
    const MCTP_CODEC_MIN_SIZE: usize = core::mem::size_of::<Self>();
}

// Default implementation of MctpCodec for types that can leverage zerocopy.
// TODO: can we generalize this to use sub-struct encodes when possible?

impl<T> MctpCodec<'_> for T
where
    T: core::fmt::Debug + Sized + FromBytes + IntoBytes + Immutable,
{
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, MctpCodecError> {
        self.write_to_prefix(buffer)
            .map_err(|_| MctpCodecError::BufferTooShort)
            .map(|_| Self::MCTP_CODEC_MIN_SIZE)
    }

    fn decode(buffer: &[u8]) -> Result<Self, MctpCodecError> {
        Ok(Self::read_from_prefix(buffer)
            .map_err(|_| MctpCodecError::BufferTooShort)?
            .0)
    }
}
