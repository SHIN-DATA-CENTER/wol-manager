//! Physical-NIC MAC discovery and OS caption over WMI/DCOM (the fix for hosts reachable only over
//! a VPN, where ARP cannot see a MAC).
//!
//! The ranking of adapters into [`MacCandidate`]s is a pure function (`rank_candidates`); the COM
//! plumbing lives behind it:
//! - a **dedicated MTA thread** per call (`CoInitializeEx` / `CoUninitialize` paired by a guard, all
//!   COM objects dropped before `CoUninitialize`, only plain data crosses the thread boundary);
//! - `IWbemLocator::ConnectServer` with the alternate credentials, then `CoSetProxyBlanket`
//!   (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, `RPC_C_IMP_LEVEL_IMPERSONATE`, [`COAUTHIDENTITY`]) on the
//!   `IWbemServices` proxy **and** on every `IEnumWbemClassObject` proxy, each also on its
//!   `IUnknown` (so `QueryInterface` / `Release` travel with the same identity);
//! - `CoInitializeSecurity` is deliberately **not** called: it is process-wide and once-only, and
//!   in the GUI process other COM users (UI Automation / accesskit) may already own it (or would be
//!   affected by our choice). Microsoft's remote-WMI sample passes the registry defaults
//!   (`RPC_C_AUTHN_LEVEL_DEFAULT`, `RPC_C_IMP_LEVEL_IDENTIFY`) there anyway; everything that matters
//!   is set per proxy, which overrides the process default.
//!
//! # Blocking
//! [`mac_candidates`] and [`os_caption`] open a DCOM connection on a worker thread. On a reachable,
//! WMI-enabled host they take a second or two; when the WMI firewall group is closed the DCOM
//! connect can block for **up to two minutes** (`WBEM_FLAG_CONNECT_USE_MAX_WAIT`). Each
//! enumeration step is bounded (60 s). Pre-probe TCP 135 and run on a worker thread.
//!
//! [`COAUTHIDENTITY`]: windows::Win32::System::Com::COAUTHIDENTITY

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::error::{Error, Op, Result};

/// The physical kind of an adapter, from `NdisPhysicalMedium`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NicKind {
    /// Wired Ethernet (`NdisPhysicalMedium` 14, 802.3).
    Physical,
    /// Wi-Fi (`NdisPhysicalMedium` 9, native 802.11).
    Wifi,
    /// Anything else.
    Other,
}

impl NicKind {
    fn from_medium(medium: i32) -> NicKind {
        match medium {
            14 => NicKind::Physical,
            9 => NicKind::Wifi,
            _ => NicKind::Other,
        }
    }
}

/// A candidate physical MAC for a host, ranked by [`MacCandidate::score`] (higher is better).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacCandidate {
    /// Adapter name (`MSFT_NetAdapter.Name`, e.g. `"Ethernet"`).
    pub iface: String,
    /// The current MAC (`NetworkAddresses[0]`, falling back to `PermanentAddress`),
    /// colon-separated uppercase (`"F4:B5:20:42:72:5C"`).
    pub mac: String,
    /// The burned-in MAC (`PermanentAddress`), when available (often equal to `mac`).
    pub permanent_mac: Option<String>,
    /// Physical kind.
    pub kind: NicKind,
    /// Whether this adapter carries an active IPv4 default route.
    pub on_default_route: bool,
    /// Whether the link is up (`MediaConnectState == 1`).
    pub link_up: bool,
    /// Ranking score; candidates are returned sorted by this descending. Only the order is
    /// meaningful.
    pub score: i32,
    /// A LAN IPv4 address and prefix length on this adapter, when known (link-local 169.254/16
    /// only when there is nothing else).
    pub lan_ipv4: Option<(Ipv4Addr, u8)>,
}

/// Raw per-adapter facts as read from `MSFT_NetAdapter` (before ranking).
#[derive(Clone, Debug, Default)]
pub(crate) struct RawAdapter {
    pub iface_index: u32,
    pub name: String,
    pub mac: Option<String>,
    pub permanent: Option<String>,
    pub connector_present: bool,
    pub hardware_interface: bool,
    pub is_virtual: bool,
    pub ndis_medium: i32,
    pub media_connect_state: i32,
}

/// Formats a 12-hex-digit MAC (no separators, e.g. `"F4B52042725C"`) as colon-separated uppercase.
/// Returns `None` for an empty, malformed, or all-zero address.
pub(crate) fn format_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    if hex.chars().all(|c| c == '0') {
        return None;
    }
    let up = hex.to_ascii_uppercase();
    let parts: Vec<String> = (0..12)
        .step_by(2)
        .map(|i| up[i..i + 2].to_owned())
        .collect();
    Some(parts.join(":"))
}

/// Total default-route metric per interface: the lowest `RouteMetric` of its active IPv4 default
/// routes plus the interface's `InterfaceMetric` (Windows orders routes by the sum). Duplicate
/// rows (several gateways, or instances from more than one policy store) never double-count.
pub(crate) fn combine_route_metrics(
    default_routes: &[(u32, i32)],
    interface_metrics: &[(u32, i32)],
) -> HashMap<u32, i32> {
    let mut route: HashMap<u32, i32> = HashMap::new();
    for &(idx, m) in default_routes {
        route
            .entry(idx)
            .and_modify(|cur| *cur = (*cur).min(m))
            .or_insert(m);
    }
    let mut iface: HashMap<u32, i32> = HashMap::new();
    for &(idx, m) in interface_metrics {
        iface
            .entry(idx)
            .and_modify(|cur| *cur = (*cur).min(m))
            .or_insert(m);
    }
    route
        .into_iter()
        .map(|(idx, r)| (idx, r.saturating_add(iface.get(&idx).copied().unwrap_or(0))))
        .collect()
}

/// One IPv4 address per interface, preferring a non-link-local (not 169.254/16) address.
pub(crate) fn pick_lan_ipv4(addrs: &[(u32, Ipv4Addr, u8)]) -> HashMap<u32, (Ipv4Addr, u8)> {
    let mut out: HashMap<u32, (Ipv4Addr, u8)> = HashMap::new();
    for &(idx, ip, prefix) in addrs {
        match out.get(&idx) {
            Some((cur, _)) if !cur.is_link_local() || ip.is_link_local() => {}
            _ => {
                out.insert(idx, (ip, prefix));
            }
        }
    }
    out
}

/// Ranks raw adapters into sorted [`MacCandidate`]s.
///
/// Candidate filter: `ConnectorPresent && HardwareInterface && !Virtual` and a usable (non-zero)
/// MAC (`NetworkAddresses[0]`, else `PermanentAddress`). Order, lexicographic: carries an IPv4
/// default route (lower total metric first), then wired (medium 14) over Wi-Fi (medium 9) over
/// other, then link up; ties by name.
pub(crate) fn rank_candidates(
    adapters: &[RawAdapter],
    default_route_metric: &HashMap<u32, i32>,
    ipv4_by_iface: &HashMap<u32, (Ipv4Addr, u8)>,
) -> Vec<MacCandidate> {
    let mut out: Vec<MacCandidate> = adapters
        .iter()
        .filter(|a| a.connector_present && a.hardware_interface && !a.is_virtual)
        .filter_map(|a| {
            let permanent_mac = a.permanent.as_deref().and_then(format_mac);
            let mac = a
                .mac
                .as_deref()
                .and_then(format_mac)
                .or_else(|| permanent_mac.clone())?;
            let metric = default_route_metric.get(&a.iface_index).copied();
            let kind = NicKind::from_medium(a.ndis_medium);
            let link_up = a.media_connect_state == 1;

            // Lexicographic score: route (with metric) >> kind >> link.
            let mut score = 0;
            if let Some(m) = metric {
                score += 100_000 + (999 - m.clamp(0, 999)) * 100;
            }
            score += match kind {
                NicKind::Physical => 20,
                NicKind::Wifi => 10,
                NicKind::Other => 0,
            };
            if link_up {
                score += 1;
            }

            Some(MacCandidate {
                iface: a.name.clone(),
                mac,
                permanent_mac,
                kind,
                on_default_route: metric.is_some(),
                link_up,
                score,
                lan_ipv4: ipv4_by_iface.get(&a.iface_index).copied(),
            })
        })
        .collect();
    // Sort by score desc, then iface name for a stable order.
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.iface.cmp(&b.iface)));
    out
}

/// Splits `DOMAIN\user` / `HOST\user` into `(domain, user)`; a UPN (`user@domain`) or a bare
/// name keeps an empty domain.
pub(crate) fn split_account(account: &str) -> (&str, &str) {
    match account.split_once('\\') {
        Some((d, u)) => (d, u),
        None => ("", account),
    }
}

/// Reads the physical-NIC MAC candidates of a host over WMI.
///
/// `host` is the management address/name (no leading backslashes; `"."` = this PC). `creds` is
/// `Some((user, pass))` for alternate credentials, or `None` to use the current logon (the process
/// identity) — valid remotely too, e.g. for a domain account that is admin on the target. If the
/// target turns out to be this PC, WMI refuses explicit credentials
/// (`WBEM_E_LOCAL_CREDENTIALS`); the call then transparently retries without them.
///
/// `credentials_validated` should be `true` when the same credentials have already been accepted by
/// an IPC$ / `NetRemoteTOD` pre-check, so that a WMI access-denied is attributed to UAC/DCOM rather
/// than a possibly-wrong password (see [`Error::from_hresult_authenticated`]).
///
/// # Blocking
/// See the module note.
#[cfg(windows)]
pub fn mac_candidates(
    host: &str,
    creds: Option<(&str, &str)>,
    credentials_validated: bool,
) -> Result<Vec<MacCandidate>> {
    let host = host.to_owned();
    let creds = windows_impl::OwnedCreds::from(creds);
    windows_impl::on_mta_thread(move || {
        windows_impl::mac_candidates_com(&host, creds.as_pair(), credentials_validated)
    })
}

/// Reads `Win32_OperatingSystem.Caption` (e.g. `"Microsoft Windows 11 Pro"`) of a host over WMI.
/// See [`mac_candidates`] for `creds` and `credentials_validated`.
///
/// # Blocking
/// See the module note.
#[cfg(windows)]
pub fn os_caption(
    host: &str,
    creds: Option<(&str, &str)>,
    credentials_validated: bool,
) -> Result<String> {
    let host = host.to_owned();
    let creds = windows_impl::OwnedCreds::from(creds);
    windows_impl::on_mta_thread(move || {
        windows_impl::os_caption_com(&host, creds.as_pair(), credentials_validated)
    })
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use crate::error::{WBEM_E_LOCAL_CREDENTIALS, WBEM_S_TIMEDOUT};
    use crate::wide::{wz, wz_secret};
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COAUTHIDENTITY, COINIT_MULTITHREADED, COLE_DEFAULT_PRINCIPAL,
        CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, EOAC_NONE,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Ole::{
        SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
    };
    use windows::Win32::System::Rpc::{
        RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };
    use windows::Win32::System::Variant::{
        VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I1, VT_I2, VT_I4, VT_UI1, VT_UI2, VT_UI4,
        VariantClear,
    };
    use windows::Win32::System::Wmi::{
        IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
        WbemLocator,
    };
    use windows::core::{BSTR, IUnknown, Interface, PCWSTR, w};
    use zeroize::{Zeroize, Zeroizing};

    /// Per-`Next` timeout. A stalled server surfaces as `WBEM_S_TIMEDOUT` instead of hanging.
    const NEXT_TIMEOUT_MS: i32 = 60_000;

    /// Owned credentials moved to the MTA thread; the password is wiped on drop.
    pub(super) struct OwnedCreds(Option<(String, Zeroizing<String>)>);

    impl OwnedCreds {
        pub(super) fn from(creds: Option<(&str, &str)>) -> Self {
            OwnedCreds(creds.map(|(u, p)| (u.to_owned(), Zeroizing::new(p.to_owned()))))
        }
        pub(super) fn as_pair(&self) -> Option<(&str, &str)> {
            self.0.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
        }
    }

    /// Balances a successful `CoInitializeEx` on this thread, also when unwinding.
    struct ComApartment;

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: constructed only after CoInitializeEx succeeded on this same thread; every
            // COM object used on the thread is dropped before this guard (declared first).
            unsafe { CoUninitialize() };
        }
    }

    /// Runs `f` on a fresh MTA thread with COM initialized, then uninitialized. COM objects are not
    /// `Send`, so `f` returns only plain data.
    pub(super) fn on_mta_thread<T, F>(f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        // A dedicated MTA thread: COM objects created here never cross the thread boundary.
        let handle = std::thread::spawn(move || {
            // SAFETY: initialize COM for this thread only.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if hr.is_err() {
                return Err(Error::from_hresult(
                    Op::Wmi,
                    hr.0,
                    "CoInitializeEx(COINIT_MULTITHREADED)",
                ));
            }
            let _apartment = ComApartment;
            f()
        });
        handle.join().map_err(|_| {
            Error::new(
                crate::error::ErrorKind::Other,
                Op::Wmi,
                "WMI worker thread panicked",
            )
        })?
    }

    /// A password BSTR whose `SysAllocString` buffer is wiped before it is freed.
    struct SecretBstr(BSTR);

    impl SecretBstr {
        fn new(s: &str) -> Self {
            let w = wz_secret(s); // NUL-terminated, pre-sized, wiped on drop
            SecretBstr(BSTR::from_wide(&w[..w.len() - 1]))
        }
    }

    impl Drop for SecretBstr {
        fn drop(&mut self) {
            let (p, n) = {
                let s: &[u16] = &self.0;
                (s.as_ptr().cast_mut(), s.len())
            };
            if n > 0 {
                // SAFETY: a non-empty BSTR owns `n` writable UTF-16 units at `p` (allocated by
                // SysAllocStringLen and freed only by BSTR's own Drop, which runs after this).
                unsafe { std::slice::from_raw_parts_mut(p, n) }.zeroize();
            }
        }
    }

    /// Credentials pinned in memory for the lifetime of the proxy blankets. All strings are
    /// NUL-terminated (the lengths exclude the NUL); an empty domain is passed as NULL, never as a
    /// dangling pointer.
    struct AuthIdentity {
        _user: Vec<u16>,
        _domain: Option<Vec<u16>>,
        _password: Zeroizing<Vec<u16>>,
        coauth: COAUTHIDENTITY,
    }

    impl AuthIdentity {
        fn new(account: &str, password: &str) -> Box<AuthIdentity> {
            let (domain, user) = split_account(account);
            let mut b = Box::new(AuthIdentity {
                _user: wz(user),
                _domain: (!domain.is_empty()).then(|| wz(domain)),
                _password: wz_secret(password),
                coauth: COAUTHIDENTITY::default(),
            });
            let (dptr, dlen) = match &b._domain {
                Some(d) => (d.as_ptr().cast_mut(), (d.len() - 1) as u32),
                None => (std::ptr::null_mut(), 0),
            };
            b.coauth = COAUTHIDENTITY {
                User: b._user.as_ptr().cast_mut(),
                UserLength: (b._user.len() - 1) as u32,
                Domain: dptr,
                DomainLength: dlen,
                Password: b._password.as_ptr().cast_mut(),
                PasswordLength: (b._password.len() - 1) as u32,
                Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE.0,
            };
            b
        }
    }

    fn auth_ptr(id: Option<&AuthIdentity>) -> Option<*const core::ffi::c_void> {
        id.map(|a| &a.coauth as *const COAUTHIDENTITY as *const core::ffi::c_void)
    }

    fn set_blanket<P: windows::core::Param<IUnknown>>(
        p: P,
        auth: Option<*const core::ffi::c_void>,
    ) -> windows::core::Result<()> {
        // SAFETY: `p` is a live COM proxy; `auth` (if any) points to a COAUTHIDENTITY whose strings
        // outlive the proxy (kept in `Ns`).
        unsafe {
            CoSetProxyBlanket(
                p,
                RPC_C_AUTHN_DEFAULT as u32,
                RPC_C_AUTHZ_DEFAULT,
                COLE_DEFAULT_PRINCIPAL,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                auth,
                EOAC_NONE,
            )
        }
    }

    /// Sets the blanket on the exact interface proxy (required: a blanket on a QI'd `IUnknown`
    /// alone leaves calls at the process default) AND on its `IUnknown` (MS "Setting
    /// Authentication": QueryInterface / Release then use the same identity).
    fn blanket<I>(itf: &I, id: Option<&AuthIdentity>) -> windows::core::Result<()>
    where
        I: Interface,
        for<'a> &'a I: windows::core::Param<IUnknown>,
    {
        let a = auth_ptr(id);
        set_blanket(itf, a)?;
        let unk: IUnknown = itf.cast()?;
        set_blanket(&unk, a)
    }

    /// A connected namespace with its (optional) alternate credentials kept alive. Field order
    /// matters: the proxy is released before the identity it references.
    struct Ns {
        svc: IWbemServices,
        id: Option<Box<AuthIdentity>>,
    }

    fn connect_server(
        loc: &IWbemLocator,
        host: &str,
        namespace: &str,
        creds: Option<(&str, &str)>,
    ) -> windows::core::Result<IWbemServices> {
        let resource = BSTR::from(format!(r"\\{host}\{namespace}"));
        let empty = BSTR::new();
        let user = creds.map_or_else(BSTR::new, |(u, _)| BSTR::from(u));
        let pass = creds.map(|(_, p)| SecretBstr::new(p));
        // SAFETY: all BSTR arguments live across the call.
        unsafe {
            loc.ConnectServer(
                &resource,
                &user,
                pass.as_ref().map_or(&empty, |p| &p.0),
                &empty,
                WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
                &empty,
                None,
            )
        }
    }

    fn connect(
        host: &str,
        namespace: &str,
        creds: Option<(&str, &str)>,
        credentials_validated: bool,
    ) -> Result<Ns> {
        // SAFETY: CoCreateInstance on an MTA thread.
        let loc: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| Error::from_windows(Op::Wmi, &e, "CoCreateInstance(WbemLocator)"))?;
        let (svc, creds) = match connect_server(&loc, host, namespace, creds) {
            Ok(svc) => (svc, creds),
            // WMI refuses explicit credentials for the local machine: the target is this PC, so
            // connect with the process identity instead.
            Err(e) if creds.is_some() && e.code().0 == WBEM_E_LOCAL_CREDENTIALS => {
                log::debug!("{host} is this PC for WMI; retrying without credentials");
                let svc = connect_server(&loc, host, namespace, None).map_err(|e| {
                    Error::from_windows(Op::Wmi, &e, "IWbemLocator::ConnectServer(local)")
                })?;
                (svc, None)
            }
            // ConnectServer access-denied is a wrong password OR UAC/DCOM; disambiguate with the
            // pre-validation flag.
            Err(e) => {
                return Err(Error::from_windows_authenticated(
                    Op::Wmi,
                    &e,
                    credentials_validated,
                    "IWbemLocator::ConnectServer",
                ));
            }
        };

        let id = creds.map(|(u, p)| AuthIdentity::new(u, p));
        blanket(&svc, id.as_deref()).map_err(|e| {
            Error::from_windows_authenticated(Op::Wmi, &e, true, "CoSetProxyBlanket(services)")
        })?;
        Ok(Ns { svc, id })
    }

    fn query(ns: &Ns, wql: &str) -> Result<IEnumWbemClassObject> {
        // SAFETY: `ns.svc` is a live services proxy.
        let en = unsafe {
            ns.svc.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(wql),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
        }
        .map_err(|e| {
            Error::from_windows_authenticated(Op::Wmi, &e, true, "IWbemServices::ExecQuery")
        })?;
        // The enumerator is a separate proxy: it needs its own blanket.
        blanket(&en, ns.id.as_deref()).map_err(|e| {
            Error::from_windows_authenticated(Op::Wmi, &e, true, "CoSetProxyBlanket(enum)")
        })?;
        Ok(en)
    }

    /// Iterates an enumerator, calling `f` for each object.
    fn for_each_object(
        en: &IEnumWbemClassObject,
        mut f: impl FnMut(&IWbemClassObject),
    ) -> Result<()> {
        loop {
            let mut row: [Option<IWbemClassObject>; 1] = [None];
            let mut n = 0u32;
            // SAFETY: `row` has room for one object; `n` receives the count.
            let hr = unsafe { en.Next(NEXT_TIMEOUT_MS, &mut row, &mut n) };
            if hr.is_err() {
                return Err(Error::from_hresult_authenticated(
                    Op::Wmi,
                    hr.0,
                    true,
                    "IEnumWbemClassObject::Next",
                ));
            }
            if n == 0 {
                if hr.0 == WBEM_S_TIMEDOUT {
                    // A success code, but the enumeration is incomplete: never return a partial set.
                    return Err(Error::from_hresult_authenticated(
                        Op::Wmi,
                        hr.0,
                        true,
                        "IEnumWbemClassObject::Next timed out",
                    ));
                }
                break; // WBEM_S_FALSE: end of the result set
            }
            if let Some(obj) = row[0].take() {
                f(&obj);
            }
        }
        Ok(())
    }

    fn get_variant(obj: &IWbemClassObject, name: PCWSTR) -> Option<VARIANT> {
        let mut v = VARIANT::default();
        // SAFETY: `obj` is a live class object; `v` is initialized and cleared by the caller.
        let ok = unsafe { obj.Get(name, 0, &mut v, None, None) }.is_ok();
        if ok { Some(v) } else { None }
    }

    fn variant_string(obj: &IWbemClassObject, name: PCWSTR) -> Option<String> {
        let mut v = get_variant(obj, name)?;
        // SAFETY: read the tagged union per its vt, then clear (frees the BSTR once).
        let out = unsafe {
            let vt = v.Anonymous.Anonymous.vt;
            let s = if vt == VT_BSTR {
                Some(v.Anonymous.Anonymous.Anonymous.bstrVal.to_string())
            } else {
                None
            };
            let _ = VariantClear(&mut v);
            s
        };
        out.filter(|s| !s.is_empty())
    }

    /// Reads any small integer property as `i32`. WMI hands `uint32`/`uint16` back as `VT_I4` but
    /// `uint8` (e.g. `PrefixLength`) as `VT_UI1`, so all integer tags are accepted.
    fn variant_i32(obj: &IWbemClassObject, name: PCWSTR) -> Option<i32> {
        let mut v = get_variant(obj, name)?;
        // SAFETY: read the union per its vt, then clear.
        unsafe {
            let a = &v.Anonymous.Anonymous.Anonymous;
            let out = match v.Anonymous.Anonymous.vt {
                t if t == VT_I4 => Some(a.lVal),
                t if t == VT_UI4 => Some(a.ulVal as i32),
                t if t == VT_I2 => Some(a.iVal as i32),
                t if t == VT_UI2 => Some(a.uiVal as i32),
                t if t == VT_UI1 => Some(a.bVal as i32),
                t if t == VT_I1 => Some(a.cVal as i32),
                _ => None,
            };
            let _ = VariantClear(&mut v);
            out
        }
    }

    fn variant_bool(obj: &IWbemClassObject, name: PCWSTR) -> Option<bool> {
        let mut v = get_variant(obj, name)?;
        // SAFETY: read per vt, then clear.
        unsafe {
            let vt = v.Anonymous.Anonymous.vt;
            let out = if vt == VT_BOOL {
                Some(v.Anonymous.Anonymous.Anonymous.boolVal.0 != 0)
            } else {
                None
            };
            let _ = VariantClear(&mut v);
            out
        }
    }

    /// Reads the first element of a one-dimensional `VT_ARRAY|VT_BSTR` property (e.g.
    /// `NetworkAddresses[0]`). `VT_NULL` / empty arrays give `None`.
    fn variant_first_bstr(obj: &IWbemClassObject, name: PCWSTR) -> Option<String> {
        let mut v = get_variant(obj, name)?;
        // SAFETY: check the array type and rank, copy element `lo` (SafeArrayGetElement returns a
        // new BSTR that `b` frees), then clear the VARIANT (destroys the SAFEARRAY once).
        let out = unsafe {
            let vt = v.Anonymous.Anonymous.vt;
            let mut result = None;
            if vt.0 == (VT_ARRAY.0 | VT_BSTR.0) {
                let sa = v.Anonymous.Anonymous.Anonymous.parray;
                if !sa.is_null()
                    && SafeArrayGetDim(sa) == 1
                    && let (Ok(lo), Ok(hi)) = (SafeArrayGetLBound(sa, 1), SafeArrayGetUBound(sa, 1))
                    && lo <= hi
                {
                    let mut b = BSTR::new();
                    if SafeArrayGetElement(sa, &lo, &mut b as *mut BSTR as *mut _).is_ok() {
                        result = Some(b.to_string());
                    }
                }
            }
            let _ = VariantClear(&mut v);
            result
        };
        out.filter(|s| !s.is_empty())
    }

    pub(super) fn mac_candidates_com(
        host: &str,
        creds: Option<(&str, &str)>,
        credentials_validated: bool,
    ) -> Result<Vec<MacCandidate>> {
        let cim = connect(host, r"root\StandardCimv2", creds, credentials_validated)?;

        // Adapters.
        let mut adapters = Vec::new();
        let en = query(
            &cim,
            "SELECT Name, InterfaceIndex, NetworkAddresses, PermanentAddress, ConnectorPresent, \
             HardwareInterface, Virtual, NdisPhysicalMedium, MediaConnectState FROM MSFT_NetAdapter",
        )?;
        for_each_object(&en, |o| {
            adapters.push(RawAdapter {
                iface_index: variant_i32(o, w!("InterfaceIndex")).unwrap_or(0) as u32,
                name: variant_string(o, w!("Name")).unwrap_or_default(),
                mac: variant_first_bstr(o, w!("NetworkAddresses")),
                permanent: variant_string(o, w!("PermanentAddress")),
                connector_present: variant_bool(o, w!("ConnectorPresent")).unwrap_or(false),
                hardware_interface: variant_bool(o, w!("HardwareInterface")).unwrap_or(false),
                is_virtual: variant_bool(o, w!("Virtual")).unwrap_or(false),
                ndis_medium: variant_i32(o, w!("NdisPhysicalMedium")).unwrap_or(-1),
                media_connect_state: variant_i32(o, w!("MediaConnectState")).unwrap_or(0),
            });
        })?;

        // Active (Store=1) IPv4 default routes and interface metrics. The persistent store would
        // add stale / duplicate rows (e.g. a static gateway on an unplugged NIC).
        let mut routes = Vec::new();
        let en = query(
            &cim,
            "SELECT InterfaceIndex, RouteMetric FROM MSFT_NetRoute \
             WHERE DestinationPrefix='0.0.0.0/0' AND Store=1",
        )?;
        for_each_object(&en, |o| {
            if let Some(idx) = variant_i32(o, w!("InterfaceIndex")) {
                routes.push((idx as u32, variant_i32(o, w!("RouteMetric")).unwrap_or(0)));
            }
        })?;

        let mut if_metrics = Vec::new();
        let en = query(
            &cim,
            "SELECT InterfaceIndex, InterfaceMetric FROM MSFT_NetIPInterface \
             WHERE AddressFamily=2 AND Store=1",
        )?;
        for_each_object(&en, |o| {
            if let Some(idx) = variant_i32(o, w!("InterfaceIndex")) {
                if_metrics.push((
                    idx as u32,
                    variant_i32(o, w!("InterfaceMetric")).unwrap_or(0),
                ));
            }
        })?;

        // IPv4 addresses per interface.
        let mut addrs = Vec::new();
        let en = query(
            &cim,
            "SELECT InterfaceIndex, IPAddress, PrefixLength FROM MSFT_NetIPAddress \
             WHERE AddressFamily=2 AND Store=1",
        )?;
        for_each_object(&en, |o| {
            if let Some(idx) = variant_i32(o, w!("InterfaceIndex"))
                && let Some(ip) = variant_string(o, w!("IPAddress"))
                && let Ok(addr) = ip.parse::<Ipv4Addr>()
            {
                let prefix = variant_i32(o, w!("PrefixLength")).unwrap_or(0).clamp(0, 32) as u8;
                addrs.push((idx as u32, addr, prefix));
            }
        })?;

        let metrics = combine_route_metrics(&routes, &if_metrics);
        Ok(rank_candidates(&adapters, &metrics, &pick_lan_ipv4(&addrs)))
    }

    pub(super) fn os_caption_com(
        host: &str,
        creds: Option<(&str, &str)>,
        credentials_validated: bool,
    ) -> Result<String> {
        let cimv2 = connect(host, r"root\cimv2", creds, credentials_validated)?;
        let en = query(&cimv2, "SELECT Caption FROM Win32_OperatingSystem")?;
        let mut caption = None;
        for_each_object(&en, |o| {
            if caption.is_none() {
                caption = variant_string(o, w!("Caption"));
            }
        })?;
        caption.ok_or_else(|| {
            Error::new(
                crate::error::ErrorKind::Unsupported,
                Op::Wmi,
                "Win32_OperatingSystem returned no Caption",
            )
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn auth_identity_strings_are_terminated_and_domain_is_null_when_empty() {
            // Regression: an empty domain used to be passed as `Vec::new().as_ptr()` (a dangling,
            // non-null pointer) and no buffer was NUL-terminated.
            let upn = AuthIdentity::new("admin@example.com", "pw");
            assert!(upn.coauth.Domain.is_null());
            assert_eq!(upn.coauth.DomainLength, 0);
            assert_eq!(upn.coauth.UserLength, "admin@example.com".len() as u32);
            // SAFETY: the buffers are owned by `upn` and NUL-terminated at the given lengths.
            unsafe {
                assert_eq!(*upn.coauth.User.add(upn.coauth.UserLength as usize), 0);
                assert_eq!(*upn.coauth.Password.add(2), 0);
            }
            let dom = AuthIdentity::new(r"PC1\admin", "");
            assert!(!dom.coauth.Domain.is_null());
            assert_eq!(dom.coauth.DomainLength, 3);
            assert_eq!(dom.coauth.UserLength, 5);
            assert_eq!(dom.coauth.PasswordLength, 0);
            // SAFETY: as above.
            unsafe {
                assert_eq!(*dom.coauth.Domain.add(3), 0);
                assert_eq!(*dom.coauth.Password, 0);
            }
        }

        #[test]
        fn secret_bstr_round_trips() {
            let b = SecretBstr::new("pässwörd🔑");
            assert_eq!(b.0.to_string(), "pässwörd🔑");
            let e = SecretBstr::new("");
            assert!(e.0.is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn adapter(
        idx: u32,
        name: &str,
        mac: &str,
        connector: bool,
        hw: bool,
        virt: bool,
        medium: i32,
        link: i32,
    ) -> RawAdapter {
        RawAdapter {
            iface_index: idx,
            name: name.to_owned(),
            mac: Some(mac.to_owned()),
            permanent: Some(mac.to_owned()),
            connector_present: connector,
            hardware_interface: hw,
            is_virtual: virt,
            ndis_medium: medium,
            media_connect_state: link,
        }
    }

    #[test]
    fn format_mac_rules() {
        assert_eq!(
            format_mac("F4B52042725C").as_deref(),
            Some("F4:B5:20:42:72:5C")
        );
        assert_eq!(
            format_mac("f4b52042725c").as_deref(),
            Some("F4:B5:20:42:72:5C")
        );
        assert_eq!(
            format_mac("F4-B5-20-42-72-5C").as_deref(),
            Some("F4:B5:20:42:72:5C")
        );
        assert_eq!(format_mac("000000000000"), None);
        assert_eq!(format_mac(""), None);
        assert_eq!(format_mac("F4B5"), None);
    }

    #[test]
    fn account_splitting() {
        assert_eq!(
            split_account(r"DESKTOP-6FDOQLK\admin"),
            ("DESKTOP-6FDOQLK", "admin")
        );
        assert_eq!(
            split_account("admin@example.com"),
            ("", "admin@example.com")
        );
        assert_eq!(split_account("admin"), ("", "admin"));
    }

    #[test]
    fn ranking_matches_local_probe_scenario() {
        // Realtek (default route, wired, up), wt0 (virtual tunnel), Bluetooth PAN.
        let adapters = vec![
            adapter(13, "Ethernet", "F4B52042725C", true, true, false, 14, 1),
            adapter(20, "wt0", "AABBCCDDEEFF", false, false, true, 0, 1),
            adapter(25, "Bluetooth", "001122334455", false, false, true, 10, 0),
        ];
        let metrics = combine_route_metrics(&[(13, 0)], &[(13, 20), (20, 5), (25, 65)]);
        let ips = pick_lan_ipv4(&[(13, "192.168.1.199".parse().unwrap(), 24)]);

        let ranked = rank_candidates(&adapters, &metrics, &ips);
        assert_eq!(ranked.len(), 1, "only the physical NIC survives the filter");
        let c = &ranked[0];
        assert_eq!(c.iface, "Ethernet");
        assert_eq!(c.mac, "F4:B5:20:42:72:5C");
        assert!(c.on_default_route);
        assert_eq!(c.kind, NicKind::Physical);
        assert!(c.link_up);
        assert_eq!(c.lan_ipv4, Some(("192.168.1.199".parse().unwrap(), 24)));
    }

    #[test]
    fn default_route_and_wired_rank_first() {
        // Two physical NICs; only one carries the default route, plus a Wi-Fi with a worse metric.
        let adapters = vec![
            adapter(1, "Eth-LAN", "AAAAAAAAAAA1", true, true, false, 14, 1),
            adapter(2, "Eth-DMZ", "AAAAAAAAAAA2", true, true, false, 14, 1),
            adapter(3, "Wi-Fi", "AAAAAAAAAAA3", true, true, false, 9, 1),
        ];
        let mut routes = HashMap::new();
        routes.insert(2u32, 25); // default route on Eth-DMZ
        routes.insert(3u32, 50); // Wi-Fi also has a default route, higher metric
        let ranked = rank_candidates(&adapters, &routes, &HashMap::new());
        let order: Vec<_> = ranked.iter().map(|c| c.iface.as_str()).collect();
        assert_eq!(order, ["Eth-DMZ", "Wi-Fi", "Eth-LAN"]);
    }

    #[test]
    fn ranking_is_lexicographic_route_metric_kind_link() {
        // Both carry a default route; the lower total metric wins even over "wired", as documented.
        let adapters = vec![
            adapter(1, "Eth", "AAAAAAAAAAA1", true, true, false, 14, 1),
            adapter(2, "Wi-Fi", "AAAAAAAAAAA2", true, true, false, 9, 1),
            adapter(3, "Eth-down", "AAAAAAAAAAA3", true, true, false, 14, 0),
            adapter(4, "Eth-up", "AAAAAAAAAAA4", true, true, false, 14, 1),
        ];
        let metrics = combine_route_metrics(&[(1, 0), (2, 0)], &[(1, 60), (2, 25)]);
        let ranked = rank_candidates(&adapters, &metrics, &HashMap::new());
        let order: Vec<_> = ranked.iter().map(|c| c.iface.as_str()).collect();
        // Without routes: wired over Wi-Fi, then link up over down.
        assert_eq!(order, ["Wi-Fi", "Eth", "Eth-up", "Eth-down"]);
    }

    #[test]
    fn route_metrics_never_double_count() {
        // Regression: duplicate interface rows used to be added twice; several default routes on
        // one interface kept the last instead of the best.
        let m = combine_route_metrics(&[(7, 50), (7, 10), (9, 0)], &[(7, 20), (7, 20), (8, 5)]);
        assert_eq!(m.get(&7), Some(&30));
        assert_eq!(m.get(&9), Some(&0));
        assert_eq!(m.get(&8), None, "no default route on 8");
    }

    #[test]
    fn lan_ipv4_prefers_non_link_local() {
        let got = pick_lan_ipv4(&[
            (1, "169.254.10.1".parse().unwrap(), 16),
            (1, "192.168.1.5".parse().unwrap(), 24),
            (2, "169.254.3.3".parse().unwrap(), 16),
            (3, "10.0.0.1".parse().unwrap(), 8),
            (3, "10.0.0.2".parse().unwrap(), 8),
        ]);
        assert_eq!(got[&1], ("192.168.1.5".parse().unwrap(), 24));
        assert_eq!(got[&2], ("169.254.3.3".parse().unwrap(), 16));
        assert_eq!(got[&3], ("10.0.0.1".parse().unwrap(), 8));
    }

    #[test]
    fn permanent_address_is_the_fallback_mac() {
        // Regression: documented as the alternate but never used; an adapter without
        // NetworkAddresses was dropped.
        let mut a = adapter(1, "Eth", "F4B52042725C", true, true, false, 14, 1);
        a.mac = None;
        let ranked = rank_candidates(&[a], &HashMap::new(), &HashMap::new());
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].mac, "F4:B5:20:42:72:5C");
    }

    #[test]
    fn zero_and_virtual_filtered_out() {
        let adapters = vec![
            adapter(1, "wt0", "000000000000", true, true, false, 14, 1), // zero MAC
            adapter(2, "virt", "AABBCCDDEEFF", true, true, true, 14, 1), // virtual
            adapter(3, "noconn", "AABBCCDDEE01", false, true, false, 14, 1), // no connector
            adapter(4, "sw", "AABBCCDDEE02", true, false, false, 14, 1), // not hardware
        ];
        let ranked = rank_candidates(&adapters, &HashMap::new(), &HashMap::new());
        assert!(ranked.is_empty());
    }
}
