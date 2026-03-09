// Copyright 2025
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use zerocopy::{FromBytes, Immutable, IntoBytes};

//As of DSP0235 1.3.3 Line 1823: "11.6 MCTP control message transmission unit size"
const MCTP_CONTROL_MTU: usize = 64;

/// Errors that can occur when encoding/decoding MCTP Control messages
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum MctpCodecError {
    /// The provided buffer is to small
    BufferTooShort,
    /// Operation is unsupported for this type
    Unsupported,
    /// Encountered invalid data (while decoding)
    InvalidData,
    /// Internal error while encoding/decoding a MCTP Control message
    ///
    /// (Feel free to file a bug report)
    InternalError,
    /// The provided buffer if of the wrong size for the type.
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
