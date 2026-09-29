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

Exit codes: 0 ok, 1 negative result (no change / host down / not on PATH), 2 usage or invalid
input, 3 not found, 4 --wait timeout, 5 network, 6 config / IO / registry, 7 permission,
10 internal error.";

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

    /// Look up the MAC address from the (IPv4) address with ARP; the computer must be on
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
