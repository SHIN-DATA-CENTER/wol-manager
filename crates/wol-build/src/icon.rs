//! Rendering application icons (a coolicons glyph on a colored rounded plate) to PNG / ICO.

use std::fs;
use std::io;
use std::path::Path;

use resvg::tiny_skia::{Pixmap, Transform};
use resvg::usvg;

/// How a glyph is placed on its plate.
#[derive(Debug, Clone, Copy)]
pub struct PlateStyle {
    /// Plate fill, e.g. `"#2563EB"`.
    pub plate: &'static str,
    /// Glyph stroke color, e.g. `"#FFFFFF"`.
    pub glyph: &'static str,
    /// Corner radius in 24-unit viewBox coordinates.
    pub radius: f32,
    /// Glyph size relative to the plate (0..1).
    pub glyph_scale: f32,
}

impl PlateStyle {
    pub const APP: PlateStyle = PlateStyle {
        plate: "#2563EB",
        glyph: "#FFFFFF",
        radius: 5.0,
        glyph_scale: 0.72,
    };
    pub const CLI: PlateStyle = PlateStyle {
        plate: "#334155",
        glyph: "#FFFFFF",
        radius: 5.0,
        glyph_scale: 0.72,
    };
}

/// Standard ICO sizes (Explorer, taskbar, shortcuts, high DPI).
pub const ICO_SIZES: &[u32] = &[16, 20, 24, 32, 40, 48, 64, 256];

/// coolicons strokes are 2 units wide; thicken them at small sizes so they stay legible
/// once the glyph is shrunk onto the plate.
pub fn stroke_width_for(size: u32) -> f32 {
    match size {
        0..=16 => 3.0,
        17..=20 => 2.8,
        21..=24 => 2.6,
        25..=32 => 2.4,
        _ => 2.2,
    }
}

/// Extracts the markup between the root `<svg ...>` start tag and `</svg>`.
fn svg_inner(svg: &str) -> &str {
    let start = svg
        .find("<svg")
        .and_then(|i| svg[i..].find('>').map(|j| i + j + 1))
        .unwrap_or(0);
    let end = svg.rfind("</svg>").unwrap_or(svg.len());
    if start <= end { &svg[start..end] } else { "" }
}

/// Builds the composite SVG document for one size.
pub fn plate_svg(glyph_svg: &str, style: PlateStyle, size: u32) -> String {
    let inner = svg_inner(glyph_svg)
        .replace("currentColor", style.glyph)
        .replace(
            "stroke-width=\"2\"",
            &format!("stroke-width=\"{}\"", stroke_width_for(size)),
        );
    let s = style.glyph_scale;
    // coolicons declare fill="none" on the root <svg>; keep that for the extracted paths,
    // otherwise they would be filled black.
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><rect x="0" y="0" width="24" height="24" rx="{r}" ry="{r}" fill="{plate}"/><g fill="none" transform="translate(12 12) scale({s}) translate(-12 -12)">{inner}</g></svg>"#,
        r = style.radius,
        plate = style.plate,
    )
}

/// Renders an SVG document whose intrinsic size is 24x24 into straight (non-premultiplied)
/// RGBA bytes of `size` x `size`.
pub fn render_rgba(svg: &str, size: u32) -> Vec<u8> {
    let tree = usvg::Tree::from_str(svg, &usvg::Options::default())
        .unwrap_or_else(|e| panic!("invalid SVG for icon rendering: {e}"));
    let mut pixmap = Pixmap::new(size, size).expect("icon size must be non-zero");
    let scale = size as f32 / tree.size().width();
    resvg::render(
        &tree,
        Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    pixmap.take_demultiplied()
}

/// Renders the glyph on its plate at one size.
pub fn render_plate(glyph_svg: &str, style: PlateStyle, size: u32) -> Vec<u8> {
    render_rgba(&plate_svg(glyph_svg, style, size), size)
}

fn encode_png(rgba: Vec<u8>, size: u32) -> io::Result<Vec<u8>> {
    let image = ico::IconImage::from_rgba_data(size, size, rgba);
    let mut out = Vec::new();
    image.write_png(&mut out)?;
    Ok(out)
}

/// Writes a PNG of the plated glyph (only if its bytes changed).
pub fn write_png(path: &Path, glyph_svg: &str, style: PlateStyle, size: u32) -> io::Result<()> {
    let png = encode_png(render_plate(glyph_svg, style, size), size)?;
    crate::write_if_changed(path, &png)?;
    Ok(())
}

/// Writes a multi-resolution `.ico` of the plated glyph (only if its bytes changed).
pub fn write_ico(path: &Path, glyph_svg: &str, style: PlateStyle, sizes: &[u32]) -> io::Result<()> {
    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    for &size in sizes {
        let image =
            ico::IconImage::from_rgba_data(size, size, render_plate(glyph_svg, style, size));
        dir.add_entry(ico::IconDirEntry::encode(&image)?);
    }
    let mut out = Vec::new();
    dir.write(&mut out)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::write_if_changed(path, &out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-written test shape; not coolicons data.
    const SQUARE: &str = r#"<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 6H18V18H6Z" stroke="currentColor" stroke-width="2"/></svg>"#;

    #[test]
    fn inner_markup_is_extracted() {
        assert_eq!(
            svg_inner(SQUARE),
            r#"<path d="M6 6H18V18H6Z" stroke="currentColor" stroke-width="2"/>"#
        );
    }

    #[test]
    fn plate_replaces_current_color_and_stroke_width() {
        let s = plate_svg(SQUARE, PlateStyle::APP, 16);
        assert!(!s.contains("currentColor"));
        assert!(s.contains("stroke=\"#FFFFFF\""));
        assert!(s.contains("stroke-width=\"3\""));
        assert!(s.contains("fill=\"#2563EB\""));
    }

    #[test]
    fn renders_opaque_plate_and_white_glyph() {
        let size = 48;
        let rgba = render_plate(SQUARE, PlateStyle::APP, size);
        assert_eq!(rgba.len(), (size * size * 4) as usize);
        let px = |x: u32, y: u32| {
            let i = ((y * size + x) * 4) as usize;
            [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
        };
        // Center of the plate: plate color, fully opaque.
        assert_eq!(px(24, 24), [0x25, 0x63, 0xEB, 0xFF]);
        // Corner outside the rounded rect: transparent.
        assert_eq!(px(0, 0)[3], 0);
    }

    #[test]
    fn writes_ico_and_png() {
        let dir = tempfile::tempdir().unwrap();
        let ico_path = dir.path().join("t.ico");
        write_ico(&ico_path, SQUARE, PlateStyle::CLI, &[16, 32]).unwrap();
        let parsed = ico::IconDir::read(std::fs::File::open(&ico_path).unwrap()).unwrap();
        assert_eq!(parsed.entries().len(), 2);

        let png_path = dir.path().join("t.png");
        write_png(&png_path, SQUARE, PlateStyle::APP, 32).unwrap();
        assert!(std::fs::read(&png_path).unwrap().starts_with(b"\x89PNG"));
    }
}
