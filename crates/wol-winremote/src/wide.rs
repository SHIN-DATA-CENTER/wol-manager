//! UTF-16 helpers shared by the Win32 wrappers (crate-internal).

use zeroize::Zeroizing;

/// `s` as a NUL-terminated UTF-16 buffer.
pub(crate) fn wz(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// `s` as a NUL-terminated UTF-16 buffer that is wiped when dropped (for passwords).
pub(crate) fn wz_secret(s: &str) -> Zeroizing<Vec<u16>> {
    let mut v = Zeroizing::new(Vec::with_capacity(s.len() + 1));
    v.extend(s.encode_utf16());
    v.push(0);
    v
}

/// Reads a NUL-terminated UTF-16 string (lossy). A null pointer gives an empty string.
///
/// # Safety
/// `p` must be null or point to a readable NUL-terminated UTF-16 string.
pub(crate) unsafe fn from_pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    // SAFETY: the caller guarantees NUL termination.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wz_is_terminated_and_roundtrips() {
        let v = wz("pässwörd日本🔑");
        assert_eq!(v.last(), Some(&0));
        // SAFETY: `v` is NUL-terminated.
        assert_eq!(unsafe { from_pwstr(v.as_ptr()) }, "pässwörd日本🔑");
        // SAFETY: null is allowed.
        assert_eq!(unsafe { from_pwstr(std::ptr::null()) }, "");
        assert_eq!(*wz_secret("ab"), vec![97, 98, 0]);
    }
}
