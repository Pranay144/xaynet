//! Sum2 message payloads.
//!
//! See the [message module] documentation since this is a private module anyways.
//!
//! [message module]: ../index.html

use std::{borrow::Borrow, ops::Range};

use anyhow::{anyhow, Context};

use crate::{
    crypto::ByteObject,
    mask::object::{serialization::MaskObjectBuffer, MaskObject},
    message::{
        traits::{FromBytes, ToBytes},
        utils::range,
        DecodeError,
    },
    ParticipantTaskSignature,
};

const SUM_SIGNATURE_RANGE: Range<usize> = range(0, ParticipantTaskSignature::LENGTH);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
/// A wrapper around a buffer that contains a [`Sum2`] message.
///
/// It provides getters and setters to access the different fields of the message safely.
pub struct Sum2Buffer<T> {
    inner: T,
}

impl<T: AsRef<[u8]>> Sum2Buffer<T> {
    /// Performs bound checks for the various message fields on `bytes` and returns a new
    /// [`Sum2Buffer`].
    ///
    /// # Errors
    /// Fails if the `bytes` are smaller than a minimal-sized sum2 message buffer.
    pub fn new(bytes: T) -> Result<Self, DecodeError> {
        let buffer = Self { inner: bytes };
        buffer
            .check_buffer_length()
            .context("not a valid Sum2Buffer")?;
        Ok(buffer)
    }

    /// Returns a `Sum2Buffer` with the given `bytes` without performing bound checks.
    ///
    /// This means that accessing the message fields may panic.
    pub fn new_unchecked(bytes: T) -> Self {
        Self { inner: bytes }
    }

    /// Performs bound checks for the various message fields on this buffer.
    pub fn check_buffer_length(&self) -> Result<(), DecodeError> {
        let len = self.inner.as_ref().len();
        if len < SUM_SIGNATURE_RANGE.end {
            return Err(anyhow!(
                "invalid buffer length: {} < {}",
                len,
                SUM_SIGNATURE_RANGE.end
            ));
        }

        // Check the length of the length of the mask field
        let _ = MaskObjectBuffer::new(&self.inner.as_ref()[SUM_SIGNATURE_RANGE.end..])
            .context("invalid masked model field")?;

        Ok(())
    }
}

impl<T: AsMut<[u8]>> Sum2Buffer<T> {
    /// Gets a mutable reference to the sum signature field.
    ///
    /// # Panics
    /// Accessing the field may panic if the buffer has not been checked before.
    pub fn sum_signature_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[SUM_SIGNATURE_RANGE]
    }

    /// Gets a mutable reference to the mask field.
    ///
    /// # Panics
    /// Accessing the field may panic if the buffer has not been checked before.
    pub fn mask_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[SUM_SIGNATURE_RANGE.end..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Sum2Buffer<&'a T> {
    /// Gets a reference to the sum signature field.
    ///
    /// # Panics
    /// Accessing the field may panic if the buffer has not been checked before.
    pub fn sum_signature(&self) -> &'a [u8] {
        &self.inner.as_ref()[SUM_SIGNATURE_RANGE]
    }

    /// Gets a reference to the mask field.
    ///
    /// # Panics
    /// Accessing the field may panic if the buffer has not been checked before.
    pub fn mask(&self) -> &'a [u8] {
        &self.inner.as_ref()[SUM_SIGNATURE_RANGE.end..]
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
/// A high level representation of a sum2 message.
///
/// These messages are sent by sum participants during the sum2 phase.
pub struct Sum2<M> {
    /// The signature of the round seed and the word "sum".
    ///
    /// This is used to determine whether a participant is selected for the sum task.
    pub sum_signature: ParticipantTaskSignature,

    /// A mask computed by the participant.
    pub mask: M,
}

impl<M> ToBytes for Sum2<M>
where
    M: Borrow<MaskObject>,
{
    fn buffer_length(&self) -> usize {
        SUM_SIGNATURE_RANGE.end + self.mask.borrow().buffer_length()
    }

    fn to_bytes<T: AsMut<[u8]>>(&self, buffer: &mut T) {
        let mut writer = Sum2Buffer::new_unchecked(buffer.as_mut());
        self.sum_signature.to_bytes(&mut writer.sum_signature_mut());
        self.mask.borrow().to_bytes(&mut writer.mask_mut());
    }
}

/// An owned version of a [`Sum2`].
pub type Sum2Owned = Sum2<MaskObject>;

impl FromBytes for Sum2Owned {
    fn from_bytes<T: AsRef<[u8]>>(buffer: &T) -> Result<Self, DecodeError> {
        let reader = Sum2Buffer::new(buffer.as_ref())?;
        Ok(Self {
            sum_signature: ParticipantTaskSignature::from_bytes(&reader.sum_signature())
                .context("invalid sum signature")?,
            mask: MaskObject::from_bytes(&reader.mask()).context("invalid mask")?,
        })
    }
}

#[cfg(test)]
pub(in crate::message) mod tests_helpers {
    use super::*;
    use crate::{crypto::ByteObject, mask::object::MaskObject};

    pub fn signature() -> (ParticipantTaskSignature, Vec<u8>) {
        let bytes = vec![0x99; ParticipantTaskSignature::LENGTH];
        let signature = ParticipantTaskSignature::from_slice(&bytes[..]).unwrap();
        (signature, bytes)
    }

    pub fn mask() -> (MaskObject, Vec<u8>) {
        use crate::mask::object::serialization::tests::{bytes, object};
        (object(), bytes())
    }

    pub fn sum2() -> (Sum2Owned, Vec<u8>) {
        let mut bytes = signature().1;
        bytes.extend(mask().1);
        let sum2 = Sum2Owned {
            sum_signature: signature().0,
            mask: mask().0,
        };
        (sum2, bytes)
    }
}

#[cfg(test)]
pub(in crate::message) mod tests {
    pub(in crate::message) use super::tests_helpers as helpers;
    use super::*;

    #[test]
    fn buffer_read() {
        let bytes = helpers::sum2().1;
        let buffer = Sum2Buffer::new(&bytes).unwrap();
        assert_eq!(buffer.sum_signature(), &helpers::signature().1[..]);
        assert_eq!(buffer.mask(), &helpers::mask().1[..]);
    }

    #[test]
    fn buffer_write() {
        let mut bytes = vec![0xff; 96];
        {
            let mut buffer = Sum2Buffer::new_unchecked(&mut bytes);
            buffer
                .sum_signature_mut()
                .copy_from_slice(&helpers::signature().1[..]);
            buffer.mask_mut().copy_from_slice(&helpers::mask().1[..]);
        }
        assert_eq!(&bytes[..], &helpers::sum2().1[..]);
    }

    #[test]
    fn encode() {
        let (sum2, bytes) = helpers::sum2();
        assert_eq!(sum2.buffer_length(), bytes.len());

        let mut buf = vec![0xff; sum2.buffer_length()];
        sum2.to_bytes(&mut buf);
        assert_eq!(buf, bytes);
    }

    #[test]
    fn decode() {
        let (sum2, bytes) = helpers::sum2();
        let parsed = Sum2Owned::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sum2);
    }
}
