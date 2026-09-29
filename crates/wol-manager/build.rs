use std::collections::HashMap;

use slint_build::{CompilerConfiguration, DefaultTranslationContext, EmbedResourcesKind};
use wol_build::icon::{self, PlateStyle};
use wol_build::slint_gen::{self, ArtImage, UiIcon};
use wol_build::winres::{self, ExeKind};
use wol_build::{Coolicons, IconRef};

/// Glyph used for the application / tray icon (coolicons has no power icon).
const APP_GLYPH: IconRef = IconRef::new("Environment", "Sun");

macro_rules! ui_icons {
    ($($prop:literal => $cat:literal / $name:literal),* $(,)?) => {
        &[$(UiIcon { property: $prop, icon: IconRef::new($cat, $name) }),*]
    };
}

/// Every coolicons glyph used by the UI, exposed as `CoolIcons.<property>`.
const UI_ICONS: &[UiIcon] = ui_icons![
    "wake" => "Communication" / "Paper_Plane",
    "add" => "Edit" / "Add_Plus",
    "edit" => "Edit" / "Edit_Pencil_01",
    "copy" => "Edit" / "Copy",
    "refresh" => "Arrow" / "Arrows_Reload_01",
    "chevron-right" => "Arrow" / "Chevron_Right",
    "chevron-down" => "Arrow" / "Chevron_Down",
    "search" => "Interface" / "Search_Magnifying_Glass",
    "settings" => "Interface" / "Settings",
    "trash" => "Interface" / "Trash_Full",
    "lock" => "Interface" / "Lock",
    "external-link" => "Interface" / "External_Link",
    "more" => "Menu" / "More_Vertical",
    "close" => "Menu" / "Close_MD",
    "host" => "System" / "Monitor",
    "online" => "System" / "Wifi_High",
    "offline" => "System" / "Wifi_Off",
    "problem" => "System" / "Wifi_Problem",
    "terminal" => "System" / "Terminal",
    "ok" => "Warning" / "Circle_Check",
    "info" => "Warning" / "Info",
    "warning" => "Warning" / "Circle_Warning",
    "help" => "Warning" / "Circle_Help",
    "folder" => "File" / "Folder_Open",
    "groups" => "File" / "Folders",
    "globe" => "Navigation" / "Globe",
    "sun" => "Environment" / "Sun",
    "moon" => "Environment" / "Moon",
];

const fn art(property: &'static str, size: u32) -> ArtImage {
    ArtImage {
        property,
        icon: APP_GLYPH,
        style: PlateStyle::APP,
        size,
    }
}

/// Plated PNGs exposed as `AppArt.<property>`.
const ART: &[ArtImage] = &[
    art("app-256", 256),
    art("app-128", 128),
    art("tray-16", 16),
    art("tray-20", 20),
    art("tray-24", 24),
    art("tray-32", 32),
];

fn main() {
    let coolicons = Coolicons::locate_or_panic();
    let out_dir = wol_build::out_dir();

    let generated = slint_gen::generate(&coolicons, &out_dir, UI_ICONS, ART);

    let config = CompilerConfiguration::new()
        .with_style("fluent".into())
        .with_library_paths(HashMap::from([(
            "coolicons".to_string(),
            generated.slint_file.clone(),
        )]))
        .embed_resources(EmbedResourcesKind::EmbedFiles)
        .with_bundled_translations("lang")
        .with_default_translation_context(DefaultTranslationContext::None);
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint compilation failed");

    let ico = generated.dir.join("art").join("app.ico");
    icon::write_ico(
        &ico,
        &coolicons.read_svg(APP_GLYPH),
        PlateStyle::APP,
        icon::ICO_SIZES,
    )
    .expect("render app.ico");
    winres::embed(ExeKind::Gui, &ico, "WoL Manager", "wol-manager.exe");
}
