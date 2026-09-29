use wol_build::icon::{self, PlateStyle};
use wol_build::winres::{self, ExeKind};
use wol_build::{Coolicons, IconRef};

const TERMINAL: IconRef = IconRef::new("System", "Terminal");

fn main() {
    let coolicons = Coolicons::locate_or_panic();
    coolicons.require(&[TERMINAL]);

    let ico = wol_build::out_dir().join("wolm.ico");
    icon::write_ico(
        &ico,
        &coolicons.read_svg(TERMINAL),
        PlateStyle::CLI,
        icon::ICO_SIZES,
    )
    .expect("render wolm.ico");
    winres::embed(
        ExeKind::Console,
        &ico,
        "WoL Manager command-line interface",
        "wolm.exe",
    );
}
