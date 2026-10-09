use core::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use core::fmt;

/// 64-byte UTF-8 slot. The game thread writes it. Serialize copies the bytes
/// out before encoding, so the atomics are not held across the rest of the JSON.
#[repr(transparent)]
pub struct AtomicText([AtomicU64; 8]);

union Transmute {
    chars: [u8; 64],
    bits: [u64; 8],
}

impl AtomicText {
    pub const fn new() -> Self {
        Self([
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ])
    }

    pub fn store_str(&self, val: &str, order: Ordering) {
        let mut chars = [0u8; 64];
        let bytes = truncate_utf8(val.as_bytes(), 63);
        chars[..bytes.len()].copy_from_slice(bytes);
        unsafe {
            let bits = Transmute { chars }.bits;
            for (slot, bit) in self.0.iter().zip(bits.iter()) {
                slot.store(*bit, order);
            }
        }
    }

    pub fn load_string(&self, order: Ordering) -> String {
        let mut bits = [0u64; 8];
        for (i, slot) in self.0.iter().enumerate() {
            bits[i] = slot.load(order);
        }
        let chars = unsafe { Transmute { bits }.chars };
        let end = chars.iter().position(|b| *b == 0).unwrap_or(chars.len());
        String::from_utf8_lossy(&chars[..end]).into_owned()
    }
}

fn truncate_utf8(bytes: &[u8], max: usize) -> &[u8] {
    if bytes.len() <= max {
        return bytes;
    }
    let mut n = max;
    while n > 0 && (bytes[n] & 0b1100_0000) == 0b1000_0000 {
        n -= 1;
    }
    &bytes[..n]
}

impl fmt::Debug for AtomicText {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.load_string(Ordering::SeqCst), f)
    }
}

impl Serialize for AtomicText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.load_string(Ordering::SeqCst))
    }
}

impl<'de> Deserialize<'de> for AtomicText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let slot = AtomicText::new();
        slot.store_str(&text, Ordering::SeqCst);
        Ok(slot)
    }
}

#[cfg(test)]
mod atomic_text_tests {
    use super::*;

    #[test]
    fn round_trips_a_short_name() {
        let slot = AtomicText::new();
        slot.store_str("Forward Air", Ordering::SeqCst);
        assert_eq!(slot.load_string(Ordering::SeqCst), "Forward Air");
        let json = serde_json::to_string(&slot).unwrap();
        assert_eq!(json, "\"Forward Air\"");
    }
}
