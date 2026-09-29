//! Command-line definition (clap derive). Help text is English in v1 (plan §6).

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};
use wol_core::i18n::LangSetting;
use wol_core::pathenv::Scope;
use wol_core::transfer::Format;

const AFTER_HELP: &str = "\
Examples:
  wolm wake NAS --wait
  wolm wake --group Lab
  wolm wake AA-BB-CC-DD-EE-FF --to 10.0.20.255
  wolm status nas; if ($LASTEXITCODE -ne 0) { wolm wake nas --wait }   (PowerShell)
  wolm status nas || wolm wake nas --wait                             (cmd.exe)
  wolm add NAS --address 192.168.1.10 --arp
  wolm path add --scope user
  wolm completions | Out-String | Invoke-Expression                   (PowerShell)

Remote management (restart / shutdown / boot time / MAC through the host):
  wolm remote set PC --kind windows --user PC\\admin --address 100.105.1.2
  wolm cred set PC                                   (asks for the password; never an argument)
  wolm remote test PC
  wolm boot-time PC
  wolm restart PC --wait
  wolm shutdown PC --delay 60 --message \"Maintenance\" --yes
  wolm remote set NAS --kind ssh --key-file $env:USERPROFILE\\.ssh\\id_ed25519  (PowerShell)
  wolm remote set NAS --kind ssh --key-file %USERPROFILE%\\.ssh\\id_ed25519     (cmd.exe)
  wolm ssh trust NAS
  wolm mac PC --save

Exit codes: 0 ok, 1 negative result (no change / host down / not on PATH / refused by the
remote host), 2 usage or invalid input, 3 not found, 4 --wait timeout, 5 network, 6 config /
IO / registry, 7 permission / authentication / SSH host key, 10 internal error.";

/// WoL Manager command-line interface: wake computers with magic packets and manage the
/// host list shared with the WoL Manager app.
#[derive(Debug, Parser)]
#[command(
    name = "wolm",
    bin_name = "wolm",
    version,
    after_help = AFTER_HELP,
    max_term_width = 100
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Flags accepted by every command.
#[derive(Debug, Clone, Args)]
#[command(next_help_heading = "Global options")]
pub struct GlobalArgs {
    /// Settings folder (default: WOL_MANAGER_CONFIG_DIR, else <app folder>\data when the
    /// portable marker exists, else %APPDATA%\wol-manager)
    #[arg(long, global = true, value_name = "DIR")]
    pub config_dir: Option<PathBuf>,

    /// Message language [auto, ja, en] (default: WOL_MANAGER_LANG, then the settings, then
    /// the OS)
    #[arg(long, global = true, value_name = "LANG")]
    pub lang: Option<LangSetting>,

    /// Print exactly one JSON document on stdout (ASCII only); errors as one JSON line on
    /// stderr
    #[arg(long, global = true)]
    pub json: bool,

    /// Do not print progress, notes and warnings
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Disable colors (NO_COLOR is also respected)
    #[arg(long, global = true)]
    pub no_color: bool,

    /// More details (repeatable)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Send magic packets to hosts or MAC addresses
    #[command(visible_alias = "w")]
    Wake(WakeArgs),

    /// Check whether hosts are online
    #[command(visible_alias = "st")]
    Status(StatusArgs),

    /// List the registered hosts
    #[command(visible_alias = "ls")]
    List(ListArgs),

    /// Show one host in detail (the SecureOn password is never shown)
    #[command(visible_alias = "info")]
    Show(ShowArgs),

    /// Register a host
    Add(AddArgs),

    /// Change a registered host (only the given fields change)
    Edit(EditArgs),

    /// Delete hosts (config.toml.bak keeps the previous version)
    #[command(visible_alias = "rm")]
    Remove(RemoveArgs),

    /// Look up the MAC address of an IPv4 address on a local subnet (ARP)
    Arp(ArpArgs),

    /// List network adapters and whether magic packets are sent through them
    #[command(visible_alias = "if")]
    Interfaces(InterfacesArgs),

    /// Export hosts as TOML, JSON or CSV
    Export(ExportArgs),

    /// Import hosts from TOML, JSON or CSV (UTF-8 or Shift_JIS)
    Import(ImportArgs),

    /// Show or change settings
    #[command(subcommand)]
    Config(ConfigCmd),

    /// Portable mode (settings in <app folder>\data)
    #[command(subcommand)]
    Portable(PortableCmd),

    /// Add or remove the wolm folder to or from PATH (never touches the settings)
    #[command(subcommand)]
    Path(PathCmd),

    /// Print a shell completion script (default: PowerShell)
    Completions(CompletionsArgs),

    /// Start the WoL Manager app (wol-manager.exe)
    Gui,

    /// Print magic packets received on a UDP port (diagnostics)
    Listen(ListenArgs),

    /// Restart hosts through their remote management (asks for confirmation)
    ///
    /// Windows hosts get a countdown with a message (--delay, --message) and can be cancelled
    /// with `wolm abort` until it ends. SSH hosts run the platform command (or the host's
    /// custom command, which the confirmation shows; with --yes it is printed on stderr) with
    /// root rights about 2 s later (the Windows options do not apply). Unsaved work may be
    /// lost.
    Restart(PowerArgs),

    /// Shut hosts down through their remote management (asks for confirmation)
    ///
    /// Same options as `restart`. With --wait, the shutdown counts as confirmed when the host
    /// stops answering three checks in a row.
    Shutdown(PowerArgs),

    /// Cancel a pending restart / shutdown countdown of a Windows host (exit 1 when nothing
    /// was pending)
    Abort(AbortArgs),

    /// Show when hosts were started (boot time on this PC's clock, and uptime)
    #[command(visible_alias = "uptime")]
    BootTime(BootTimeArgs),

    /// Find the MAC address of a host or an address: ARP on the local network, else the
    /// host's remote management (VPN peers)
    Mac(MacArgs),

    /// Set up remote management of a host (Windows or SSH)
    #[command(subcommand)]
    Remote(RemoteCmd),

    /// Passwords for remote management (Windows Credential Manager; never in config.toml)
    #[command(subcommand)]
    Cred(CredCmd),

    /// SSH host keys of hosts managed over SSH
    #[command(subcommand)]
    Ssh(SshCmd),
}

/// `restart` / `shutdown`.
#[derive(Debug, Args)]
pub struct PowerArgs {
    /// Registered hosts (name, id, id prefix or MAC) with remote management
    #[arg(value_name = "HOST", required = true)]
    pub hosts: Vec<String>,

    /// Windows: countdown before it happens, 0 to 600 s, e.g. 30, 2m (default:
    /// remote.shutdown_delay_secs)
    #[arg(long, value_name = "SECS")]
    pub delay: Option<String>,

    /// Windows: no countdown (same as --delay 0; cannot be cancelled)
    #[arg(long, conflicts_with = "delay")]
    pub now: bool,

    /// Windows: close applications without asking; unsaved work is lost (default:
    /// remote.force_apps_closed)
    #[arg(long)]
    pub force: bool,

    /// Windows: let applications ask to save first (the restart may then not happen)
    #[arg(long, conflicts_with = "force")]
    pub no_force: bool,

    /// Windows: message shown on the host during the countdown
    #[arg(long, value_name = "TEXT", allow_hyphen_values = true)]
    pub message: Option<String>,

    /// Wait until the restart / shutdown is confirmed (exit 4 on timeout, Ctrl+C cancels)
    #[arg(long)]
    pub wait: bool,

    /// How long --wait waits, e.g. 5m (default: remote.restart_verify_timeout_secs or
    /// remote.shutdown_verify_timeout_secs; a Windows countdown is added)
    #[arg(long, value_name = "DURATION", requires = "wait")]
    pub timeout: Option<String>,

    /// Do not ask for confirmation (required when stdin is not a console)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct AbortArgs {
    /// Registered Windows host with remote management
    #[arg(value_name = "HOST")]
    pub host: String,
}

#[derive(Debug, Args)]
pub struct BootTimeArgs {
    /// Registered hosts with remote management (default: every such host; then a Windows
    /// host without a saved password is only asked when the use of your Windows sign-in was
    /// confirmed for it, e.g. by naming it once)
    #[arg(value_name = "HOST")]
    pub hosts: Vec<String>,
}

#[derive(Debug, Args)]
pub struct MacArgs {
    /// Registered host (name, id, id prefix or MAC), or an IPv4 address / host name
    #[arg(value_name = "HOST|IP")]
    pub target: String,

    /// Store the MAC address in the host (the best candidate, or the one chosen with
    /// --pick; asks on a console when several fit equally well)
    #[arg(long)]
    pub save: bool,

    /// Choose candidate N (1 = first in the list)
    #[arg(long, value_name = "N")]
    pub pick: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum RemoteCmd {
    /// Set up or change the remote management of a host (only the given fields change)
    ///
    /// Windows hosts: restart / shutdown / boot time over SMB (TCP 445) and the MAC over WMI,
    /// with an administrator account of the host (store its password with `wolm cred set`;
    /// without one, the current Windows sign-in is used). SSH hosts (Linux, Proxmox, NAS,
    /// FreeBSD): a key file and / or a password, root or sudo. Values are checked like in
    /// the app; Windows PowerShell 5.1 drops "" arguments, so use the --clear-* flags.
    Set(RemoteSetArgs),
    /// Turn remote management off (asks first); also deletes the host's stored passwords and
    /// its trusted SSH host key
    Clear(RemoteClearArgs),
    /// Show the remote management of a host and which passwords are stored (never the
    /// passwords; exit 1 when it is not set up)
    Show(RemoteHostArg),
    /// Connect and show the OS, the boot time and whether the account has administrator /
    /// root rights
    Test(RemoteHostArg),
}

#[derive(Debug, Args)]
pub struct RemoteHostArg {
    /// Name, id, id prefix or MAC
    #[arg(value_name = "HOST")]
    pub host: String,
}

#[derive(Debug, Args)]
pub struct RemoteClearArgs {
    /// Name, id, id prefix or MAC
    #[arg(value_name = "HOST")]
    pub host: String,

    /// Do not ask for confirmation (required when stdin is not a console)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RemoteSetArgs {
    /// Name, id, id prefix or MAC
    #[arg(value_name = "HOST")]
    pub host: String,

    /// windows or ssh (needed when the host has no remote management yet)
    #[arg(long, value_name = "KIND")]
    pub kind: Option<String>,

    /// Windows: account (PC\user, DOMAIN\user, user@domain; default: the account stored with
    /// the password, else the current sign-in). SSH: login user (default: root)
    #[arg(long, value_name = "USER", conflicts_with = "clear_user")]
    pub user: Option<String>,

    /// Address for remote management when it differs from the host's address (e.g. the
    /// VPN address)
    #[arg(long, value_name = "IPV4|NAME", conflicts_with = "clear_address")]
    pub address: Option<String>,

    /// SSH port (default: 22)
    #[arg(long, value_name = "PORT", conflicts_with = "clear_port")]
    pub port: Option<String>,

    /// SSH private key file (default: password login); its passphrase goes to `wolm cred
    /// set HOST --kind key-passphrase`
    #[arg(long, value_name = "PATH", conflicts_with = "clear_key_file")]
    pub key_file: Option<String>,

    /// SSH: how restart / shutdown get root rights [auto, root, nopasswd, password, separate]
    #[arg(long, value_name = "MODE")]
    pub sudo: Option<String>,

    /// SSH: command that restarts the host instead of the platform default (NAS firmwares)
    #[arg(
        long,
        value_name = "COMMAND",
        allow_hyphen_values = true,
        conflicts_with = "clear_reboot_command"
    )]
    pub reboot_command: Option<String>,

    /// SSH: command that powers the host off instead of the platform default
    #[arg(
        long,
        value_name = "COMMAND",
        allow_hyphen_values = true,
        conflicts_with = "clear_shutdown_command"
    )]
    pub shutdown_command: Option<String>,

    /// Remove the user name
    #[arg(long)]
    pub clear_user: bool,

    /// Use the host's address again
    #[arg(long)]
    pub clear_address: bool,

    /// Use port 22 again
    #[arg(long)]
    pub clear_port: bool,

    /// Remove the key file (password login)
    #[arg(long)]
    pub clear_key_file: bool,

    /// Use the platform's restart command again
    #[arg(long)]
    pub clear_reboot_command: bool,

    /// Use the platform's power-off command again
    #[arg(long)]
    pub clear_shutdown_command: bool,

    /// Replace remote settings that a newer version of WoL Manager wrote without asking
    /// (required when stdin is not a console)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum CredCmd {
    /// Store a password for a host (asked on the console, or read with --password-stdin;
    /// never given as an argument)
    ///
    /// Windows hosts: the administrator account's password (login). SSH hosts: the login
    /// password, the key passphrase (key-passphrase) or a separate sudo password (sudo).
    /// Passwords are kept in Windows Credential Manager for this Windows user on this PC; they
    /// are not in config.toml, exports or the portable data folder.
    Set(CredSetArgs),
    /// Delete stored passwords of a host (every kind without --kind; exit 1 when none was
    /// stored)
    Delete(CredDeleteArgs),
    /// List the stored passwords: host, kind and user name (never the passwords)
    List,
    /// Delete stored passwords of hosts that are no longer in these settings
    ///
    /// Passwords of a host that still exists are kept, also when it has no remote management
    /// (`wolm cred delete HOST` removes those). Other settings folders (portable copies,
    /// --config-dir) share the stored passwords of this Windows user: prune only with the
    /// settings that have all your hosts.
    Prune(CredPruneArgs),
}

#[derive(Debug, Args)]
pub struct CredSetArgs {
    /// Name, id, id prefix or MAC
    #[arg(value_name = "HOST")]
    pub host: String,

    /// login, key-passphrase or sudo
    #[arg(long, value_name = "KIND", default_value = "login")]
    pub kind: String,

    /// Account stored with the password (default: the host's remote user; Windows: else the
    /// current sign-in, SSH: else root)
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,

    /// Read the password from stdin (UTF-8, at most 64 KiB, one trailing line break removed)
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Args)]
pub struct CredDeleteArgs {
    /// Name, id, id prefix or MAC (or the full id of a removed host)
    #[arg(value_name = "HOST")]
    pub host: String,

    /// Only this kind: login, key-passphrase or sudo
    #[arg(long, value_name = "KIND")]
    pub kind: Option<String>,
}

#[derive(Debug, Args)]
pub struct CredPruneArgs {
    /// Only list what would be deleted
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Do not ask for confirmation (required when stdin is not a console)
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum SshCmd {
    /// Read the SSH host key of a host (without logging in), show its fingerprint and trust it
    ///
    /// Compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the
    /// host. Without --fingerprint or --accept-new it asks on the console.
    Trust(SshTrustArgs),
    /// Forget the trusted SSH host key of a host (the next connection asks again; exit 1 when
    /// none was trusted)
    Forget(RemoteHostArg),
}

#[derive(Debug, Args)]
pub struct SshTrustArgs {
    /// Name, id, id prefix or MAC
    #[arg(value_name = "HOST")]
    pub host: String,

    /// Trust the key only if it has this fingerprint (SHA256:... as ssh-keygen -lf prints it)
    #[arg(long, value_name = "SHA256:...", conflicts_with = "accept_new")]
    pub fingerprint: Option<String>,

    /// Trust the key the host presents without asking (only when no key is trusted yet)
    #[arg(long)]
    pub accept_new: bool,
}

#[derive(Debug, Args)]
pub struct WakeArgs {
    /// Registered hosts (name, id, id prefix or MAC) or bare MAC addresses
    #[arg(value_name = "HOST|MAC")]
    pub targets: Vec<String>,

    /// Wake every host of a group (repeatable)
    #[arg(short, long, value_name = "GROUP")]
    pub group: Vec<String>,

    /// Wake every registered host
    #[arg(long)]
    pub all: bool,

    /// Wake a MAC address without looking up registered hosts (repeatable)
    #[arg(long, value_name = "MAC")]
    pub mac: Vec<String>,

    /// UDP port (default: the host's port, else wake.port)
    #[arg(long, value_name = "PORT")]
    pub port: Option<String>,

    /// SecureOn password (6 bytes, e.g. 01:23:45:67:89:AB)
    #[arg(long, value_name = "PASSWORD")]
    pub secureon: Option<String>,

    /// Also send to this address (repeatable), e.g. 10.0.20.255 or relay.lan:9
    #[arg(long = "to", value_name = "ADDR[:PORT]")]
    pub to: Vec<String>,

    /// Send only through this adapter: GUID, name, index or IPv4 (repeatable)
    #[arg(long, value_name = "ADAPTER")]
    pub interface: Vec<String>,

    /// Also use VPN / virtual adapters and ignore pinned adapters
    #[arg(long, conflicts_with = "interface")]
    pub all_interfaces: bool,

    /// Do not send broadcasts (only unicast and --to targets)
    #[arg(long)]
    pub no_broadcast: bool,

    /// Rounds of packets, 1..=10 (default: wake.repeat)
    #[arg(long, value_name = "N")]
    pub repeat: Option<String>,

    /// Pause between rounds in ms, 0..=5000 (default: wake.interval_ms)
    #[arg(long, value_name = "MS")]
    pub interval_ms: Option<String>,

    /// Show the send plan and the packet without sending
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Wait until the hosts answer (exit 4 on timeout)
    #[arg(long)]
    pub wait: bool,

    /// How long --wait waits, e.g. 90s, 2m (default: wake.verify_timeout_secs)
    #[arg(long, value_name = "DURATION", requires = "wait")]
    pub timeout: Option<String>,

    /// Interval between checks while waiting (default: 2s)
    #[arg(long, value_name = "DURATION", requires = "wait")]
    pub poll: Option<String>,

    /// Status check used by --wait [auto, icmp, tcp, none]
    #[arg(long, value_name = "METHOD", requires = "wait")]
    pub probe: Option<String>,

    /// TCP port(s) used by --wait (repeatable or comma separated)
    #[arg(long = "tcp-port", value_name = "PORT", requires = "wait")]
    pub tcp_port: Vec<String>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Registered hosts (default: all) or IPv4 addresses
    #[arg(value_name = "HOST")]
    pub hosts: Vec<String>,

    /// Check every host of a group (repeatable)
    #[arg(short, long, value_name = "GROUP")]
    pub group: Vec<String>,

    /// Check every host (the default without HOST or --group)
    #[arg(long)]
    pub all: bool,

    /// Status check [auto, icmp, tcp, none] (default: per host, else probe.method)
    #[arg(long, value_name = "METHOD")]
    pub probe: Option<String>,

    /// TCP port(s) for the TCP check (repeatable or comma separated)
    #[arg(long = "tcp-port", value_name = "PORT")]
    pub tcp_port: Vec<String>,

    /// Timeout of one check, 100ms to 30s, e.g. 500ms, 2s (default: probe.timeout_ms)
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Only this group
    #[arg(short, long, value_name = "GROUP")]
    pub group: Option<String>,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Name, id, id prefix or MAC
    #[arg(value_name = "HOST")]
    pub host: String,
}

/// Host fields shared by `add` and `edit`. Values are parsed by wol-core (full-width input
/// is accepted).
#[derive(Debug, Args)]
pub struct HostFields {
    /// MAC address (AA:BB:CC:DD:EE:FF, AA-BB-.., AABB.CCDD.EEFF, AABBCCDDEEFF)
    #[arg(long, value_name = "MAC")]
    pub mac: Option<String>,

    /// Look up the MAC address from the address: ARP on the local network (the computer must
    /// be on), else, for `edit`, the host's remote management (VPN peers; a new host behind a
    /// VPN: add it with a placeholder MAC, set up `wolm remote`, then `wolm mac HOST --save`)
    #[arg(long, conflicts_with = "mac")]
    pub arp: bool,

    /// IPv4 address or host name (status checks and on-link unicast)
    #[arg(long, value_name = "IPV4|NAME")]
    pub address: Option<String>,

    /// Group
    #[arg(short, long, value_name = "GROUP")]
    pub group: Option<String>,

    /// UDP port override
    #[arg(long, value_name = "PORT")]
    pub port: Option<String>,

    /// SecureOn password (stored in plain text)
    #[arg(long, value_name = "PASSWORD")]
    pub secureon: Option<String>,

    /// Additional target (repeatable; `edit` replaces the list)
    #[arg(long = "to", value_name = "ADDR[:PORT]")]
    pub to: Vec<String>,

    /// Pin an adapter: GUID, name, index or IPv4 (repeatable; `edit` replaces the list)
    #[arg(long, value_name = "ADAPTER")]
    pub interface: Vec<String>,

    /// Status check [auto, icmp, tcp, none]
    #[arg(long, value_name = "METHOD")]
    pub probe: Option<String>,

    /// TCP port(s) for the status check (repeatable or comma separated)
    #[arg(long = "tcp-port", value_name = "PORT")]
    pub tcp_port: Vec<String>,

    /// Notes
    #[arg(long, value_name = "TEXT")]
    pub notes: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Host name (1-64 characters, unique, must not look like a MAC address)
    pub name: String,

    #[command(flatten)]
    pub fields: HostFields,

    /// Do not send subnet broadcasts for this host
    #[arg(long)]
    pub no_broadcast: bool,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// Name, id, id prefix or MAC of the host to change
    #[arg(value_name = "HOST")]
    pub host: String,

    /// New name
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    #[command(flatten)]
    pub fields: HostFields,

    /// Send subnet broadcasts for this host
    #[arg(long, conflicts_with = "no_broadcast")]
    pub broadcast: bool,

    /// Do not send subnet broadcasts for this host
    #[arg(long)]
    pub no_broadcast: bool,

    /// Remove the address
    #[arg(long, conflicts_with_all = ["address", "arp"])]
    pub clear_address: bool,

    /// Remove the group
    #[arg(long, conflicts_with = "group")]
    pub clear_group: bool,

    /// Remove the notes
    #[arg(long, conflicts_with = "notes")]
    pub clear_notes: bool,

    /// Use the default port again
    #[arg(long, conflicts_with = "port")]
    pub clear_port: bool,

    /// Remove the SecureOn password
    #[arg(long, conflicts_with = "secureon")]
    pub clear_secureon: bool,

    /// Remove all additional targets
    #[arg(long, conflicts_with = "to")]
    pub clear_targets: bool,

    /// Unpin all adapters
    #[arg(long, conflicts_with = "interface")]
    pub clear_interfaces: bool,

    /// Use the default status check again
    #[arg(long, conflicts_with = "probe")]
    pub clear_probe: bool,

    /// Use the default TCP ports again
    #[arg(long, conflicts_with = "tcp_port")]
    pub clear_tcp_ports: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Name, id, id prefix or MAC (one or more)
    #[arg(value_name = "HOST", required = true)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ArpArgs {
    /// IPv4 address on a local subnet
    #[arg(value_name = "IP")]
    pub ip: String,
}

#[derive(Debug, Args)]
pub struct InterfacesArgs {
    /// Also list adapters that are down, loopback or without IPv4
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Output format [toml, json, csv] (default: from the -o extension, else toml; json with
    /// --json). With --json and no -o, toml / csv are printed as {"format", "content"}
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<Format>,

    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Also export [settings] (TOML / JSON only)
    #[arg(long)]
    pub include_settings: bool,

    /// Only the hosts of this group
    #[arg(short, long, value_name = "GROUP")]
    pub group: Option<String>,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// File to import ("-" = stdin)
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Input format [toml, json, csv] (default: from the extension or the content)
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<Format>,

    /// Replace the host list instead of merging into it
    #[arg(long)]
    pub replace: bool,

    /// Skip invalid records instead of failing
    #[arg(long)]
    pub skip_invalid: bool,

    /// Show what would change without saving
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Also import [settings] when the file has them
    #[arg(long)]
    pub include_settings: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print the path of config.toml
    Path,
    /// Print config.toml (the defaults when it does not exist yet)
    Show,
    /// Print one setting, or all settings without KEY
    Get {
        /// Dotted key, e.g. wake.repeat
        key: Option<String>,
    },
    /// Change a setting (--clear empties a list)
    ///
    /// Lists (wake.interfaces, probe.tcp_ports) are comma separated. --clear empties a list;
    /// it is the same as the value "", which Windows PowerShell 5.1 does not pass to programs
    /// (write '""' there, or use --clear).
    Set {
        /// Dotted key, e.g. wake.repeat
        key: String,
        /// New value
        #[arg(allow_hyphen_values = true, required_unless_present = "clear")]
        value: Option<String>,
        /// Empty a list setting (same as the value "")
        #[arg(long, conflicts_with = "value")]
        clear: bool,
    },
    /// Open config.toml in Notepad (or in VISUAL / EDITOR when set)
    Open,
    /// Check config.toml (exit 1 when there are problems)
    Validate,
}

#[derive(Debug, Subcommand)]
pub enum PortableCmd {
    /// Show whether portable mode is on (exit 1 when off)
    Status,
    /// Turn portable mode on (refused for installed copies)
    Enable {
        /// Copy the current settings into the data folder (unless it has settings already)
        #[arg(long)]
        copy_settings: bool,
    },
    /// Turn portable mode off (the data folder is kept)
    Disable,
}

#[derive(Debug, Subcommand)]
pub enum PathCmd {
    /// Append DIR to PATH (exit 0 added, 1 already present)
    ///
    /// A folder that every user of this computer may change (e.g. one created directly
    /// under C:\) gets a warning, and is not put on the system PATH without --force.
    Add(PathAddArgs),
    /// Remove DIR from PATH (exit 0 removed, 1 not present)
    Remove(PathArgs),
    /// Check whether DIR is on PATH (exit 0 present, 1 not present)
    Status(PathArgs),
}

#[derive(Debug, Args)]
pub struct PathArgs {
    /// Which PATH [user, machine]
    #[arg(long, value_name = "SCOPE", default_value = "user")]
    pub scope: Scope,

    /// Folder (default: the folder of wolm.exe)
    #[arg(value_name = "DIR")]
    pub dir: Option<String>,
}

#[derive(Debug, Args)]
pub struct PathAddArgs {
    #[command(flatten)]
    pub path: PathArgs,

    /// Add a folder that every user may change to the system PATH anyway
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell
    #[arg(value_enum, value_name = "SHELL")]
    pub shell: Option<clap_complete::Shell>,
}

#[derive(Debug, Args)]
pub struct ListenArgs {
    /// UDP port
    #[arg(long, value_name = "PORT", default_value = "9")]
    pub port: String,

    /// Local address to bind
    #[arg(long, value_name = "IPV4", default_value = "0.0.0.0")]
    pub bind: String,

    /// Exit after N magic packets
    #[arg(long, value_name = "N")]
    pub count: Option<String>,

    /// Exit after this time, e.g. 30s (exit 4 when --count was not reached)
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
