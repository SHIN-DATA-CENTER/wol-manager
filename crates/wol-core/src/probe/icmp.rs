//! ICMP echo through `IcmpSendEcho` (iphlpapi). Works without administrator rights, unlike
//! raw sockets.

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, IP_SUCCESS, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
};

/// First and last `IP_*` status codes (11001..=11050): "no reply / unreachable", not an API
/// failure.
const IP_STATUS_BASE: i32 = 11000;
const IP_STATUS_LAST: i32 = 11050;

/// Win32 errors `IcmpSendEcho` reports when the destination simply cannot be reached (no
/// route, host or network unreachable, host down). Seen for example for 240.0.0.1 and when
/// the PC is offline: ERROR_NETWORK_UNREACHABLE (1231), ERROR_HOST_UNREACHABLE (1232),
/// ERROR_PROTOCOL_UNREACHABLE (1233), ERROR_PORT_UNREACHABLE (1234), ERROR_HOST_DOWN (1256).
const UNREACHABLE_ERRORS: [i32; 5] = [1231, 1232, 1233, 1234, 1256];

/// `true` when a failing `IcmpSendEcho`'s last error means "no reply" (the host is offline or
/// unreachable) rather than an API failure such as an invalid parameter or a small buffer.
pub(crate) fn is_no_reply_error(code: i32) -> bool {
    (code > IP_STATUS_BASE && code <= IP_STATUS_LAST) || UNREACHABLE_ERRORS.contains(&code)
}

/// Payload sent with each echo request.
const PAYLOAD: &[u8; 32] = b"wol-manager probe 0123456789abcd";

/// Closes the ICMP handle on drop.
struct IcmpHandle(HANDLE);

impl IcmpHandle {
    fn open() -> io::Result<IcmpHandle> {
        // SAFETY: plain FFI call without arguments.
        let h = unsafe { IcmpCreateFile() };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(IcmpHandle(h))
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from IcmpCreateFile and is closed exactly once.
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}

/// Decides whether an `IcmpSendEcho` result means "alive": at least one reply, status
/// `IP_SUCCESS`, and the reply comes from the destination itself (a router's "destination
/// unreachable" also counts as a reply). Addresses are network-order `u32`s as used by the
/// API (`u32::from_ne_bytes(octets)`).
pub fn classify(ret: u32, status: u32, reply_addr: u32, dest: u32) -> bool {
    ret > 0 && status == IP_SUCCESS && reply_addr == dest
}

/// Reply buffer size in bytes: one reply + payload + 8 bytes for an ICMP error, plus slack.
fn reply_buffer_len() -> usize {
    size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 64
}

/// Sends one echo request. `Ok(Some(rtt))` when the host answered, `Ok(None)` for no reply
/// (timeout, `IP_*` status, no route / network or host unreachable), `Err` for API failures.
///
/// **Blocking** up to `timeout`.
pub fn ping(ip: Ipv4Addr, timeout: Duration) -> io::Result<Option<Duration>> {
    let handle = IcmpHandle::open()?;
    let dest = u32::from_ne_bytes(ip.octets());
    // u64 elements guarantee the alignment ICMP_ECHO_REPLY (which contains pointers) needs.
    let mut buf: Vec<u64> = vec![0; reply_buffer_len().div_ceil(8)];
    let timeout_ms = u32::try_from(timeout.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);
    // SAFETY: the handle is valid, the request buffer is PAYLOAD, the reply buffer is
    // `buf.len() * 8` bytes, writable and 8-byte aligned.
    let ret = unsafe {
        IcmpSendEcho(
            handle.0,
            dest,
            PAYLOAD.as_ptr().cast(),
            PAYLOAD.len() as u16,
            std::ptr::null(),
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            timeout_ms,
        )
    };
    if ret == 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(code) if is_no_reply_error(code) => Ok(None),
            _ => Err(e),
        };
    }
    // SAFETY: ret > 0, so the buffer starts with an initialized ICMP_ECHO_REPLY; the buffer
    // is aligned for it. Only plain integer fields are read.
    let reply = unsafe { &*(buf.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
    if classify(ret, reply.Status, reply.Address, dest) {
        Ok(Some(Duration::from_millis(u64::from(reply.RoundTripTime))))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_rules() {
        let dest = u32::from_ne_bytes([192, 0, 2, 1]);
        let router = u32::from_ne_bytes([192, 0, 2, 254]);
        assert!(classify(1, IP_SUCCESS, dest, dest));
        assert!(!classify(0, IP_SUCCESS, dest, dest));
        // Destination unreachable from a router: a reply, but not success.
        assert!(!classify(1, 11003, router, dest));
        // Success status from another address.
        assert!(!classify(1, IP_SUCCESS, router, dest));
    }

    #[test]
    fn unreachable_errors_mean_no_reply() {
        use windows_sys::Win32::Foundation::{
            ERROR_HOST_DOWN, ERROR_HOST_UNREACHABLE, ERROR_INSUFFICIENT_BUFFER,
            ERROR_INVALID_PARAMETER, ERROR_NETWORK_UNREACHABLE, ERROR_NOT_ENOUGH_MEMORY,
            ERROR_PORT_UNREACHABLE, ERROR_PROTOCOL_UNREACHABLE,
        };
        for code in [
            ERROR_NETWORK_UNREACHABLE,
            ERROR_HOST_UNREACHABLE,
            ERROR_PROTOCOL_UNREACHABLE,
            ERROR_PORT_UNREACHABLE,
            ERROR_HOST_DOWN,
            11003, // IP_DEST_HOST_UNREACHABLE
            11010, // IP_REQ_TIMED_OUT
            11050, // IP_GENERAL_FAILURE
        ] {
            assert!(is_no_reply_error(code as i32), "{code}");
        }
        for code in [
            ERROR_INVALID_PARAMETER,
            ERROR_INSUFFICIENT_BUFFER,
            ERROR_NOT_ENOUGH_MEMORY,
            11000,
            11051,
        ] {
            assert!(!is_no_reply_error(code as i32), "{code}");
        }
    }

    /// Class E has no route: IcmpSendEcho fails with ERROR_NETWORK_UNREACHABLE, which is
    /// "offline", not an API failure.
    #[test]
    fn no_route_is_no_reply() {
        let r = ping(Ipv4Addr::new(240, 0, 0, 1), Duration::from_millis(300));
        assert!(matches!(r, Ok(None)), "{r:?}");
    }

    #[test]
    fn byte_order_is_network_order_in_memory() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let v = u32::from_ne_bytes(ip.octets());
        assert_eq!(v.to_ne_bytes(), [192, 168, 1, 10]);
    }

    #[test]
    fn reply_buffer_is_large_enough() {
        let bytes = reply_buffer_len().div_ceil(8) * 8;
        assert!(bytes >= size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8);
    }
}
