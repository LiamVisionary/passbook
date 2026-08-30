// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rizzma, Inc.
//! The veil — a revealed credential this window can show but cannot read.
//!
//! Every other value in this app passes straight through to the webview, which
//! was fine while the only question was who may *have* a credential. It stops
//! being fine once the reader might be an agent, for two reasons that have
//! nothing to do with policy:
//!
//!   - A JavaScript string cannot be erased. `delete values[k]` drops a
//!     reference; the bytes go back to the allocator un-overwritten and stay
//!     there until something happens to reuse the span. And one reveal is not
//!     one copy — escaping, the row template, the page concatenation and
//!     `innerHTML` each make another, so a value left on screen while somebody
//!     types one letter in the search box mints a fresh set nothing can erase.
//!   - Text in a webview is published to the platform accessibility tree.
//!     `AXUIElementCopyAttributeValue` and UI Automation read it with no
//!     screenshot involved, so hiding the window from capture protects nothing
//!     a screen reader could have read — and an agent reads what a screen
//!     reader reads.
//!
//! So the value stops crossing the boundary. It is held here, rasterised here,
//! and the window is handed pixels and a token. There is no string to scrape
//! and no text to publish, and `Zeroizing` lets this side do what the webview
//! could not: overwrite the bytes when the hold ends.
//!
//! What this does not buy, written down rather than implied: the plaintext is
//! in this process for as long as the hold lasts, and same-uid still means a
//! caller willing to write custom code can read it out of here. This removes
//! the copies and puts a clock on the original. It does not move the wall.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};


/// How long the CLI-side value stays held.
///
/// Deliberately longer than the window's own auto-hide (`HIDE_AFTER` in the
/// page). The two clocks race on every reveal, and the one that must win is the
/// window's: a token that expired first would leave the image 404ing under a
/// row that still says it is showing you something, which reads as a bug rather
/// than as a hold ending.
pub const HOLD: Duration = Duration::from_secs(45);

/// The largest bitmap this will produce, in pixels.
///
/// A credential is one line. This exists so a pathological value — a pasted
/// private key, a file that ended up in the store — cannot ask this process to
/// allocate a gigabyte on a path a mis-click can reach.
const MAX_PIXELS: usize = 8_000_000;
const MAX_CHARS: usize = 4096;

/// What a token stands for.
///
/// Pictures, not values. A credential is drawn the moment it is revealed and
/// the plaintext is dropped immediately after, so the window's 30 seconds and
/// the hold's 45 are a clock on an *image* — the value itself exists in this
/// process for the microseconds it takes to rasterise.
///
/// It also means the two ways of getting here converge. On a machine that seals
/// reads the drawing happens in a process the broker started and this side
/// never sees the plaintext at all; on one that does not, it happens here. Both
/// end up holding the same thing, and everything downstream of this struct
/// stops needing to know which.
struct Held {
    picture: Vec<u8>,
    born: Instant,
}

fn store() -> &'static Mutex<HashMap<String, Held>> {
    static STORE: OnceLock<Mutex<HashMap<String, Held>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A token nobody can guess and nothing can derive from the key's name.
///
/// 256 bits from the OS. It travels to the window and back over loopback, and
/// it is the only thing standing between another process on this machine and a
/// picture of a credential, so it is not a counter and not a hash of anything.
fn token() -> String {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("the OS has no randomness");
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Drop everything past its hold. Called on every touch of the store, so a
/// window that is left open does not accumulate values nobody is looking at.
fn sweep(map: &mut HashMap<String, Held>) {
    map.retain(|_, held| held.born.elapsed() < HOLD);
}

/// Put a drawn credential behind a token.
pub fn hold(picture: Vec<u8>) -> String {
    let mark = token();
    let mut map = store().lock().unwrap_or_else(|e| e.into_inner());
    sweep(&mut map);
    map.insert(mark.clone(), Held { picture, born: Instant::now() });
    mark
}

/// Forget one held value now, overwriting it rather than dropping it.
///
/// `Zeroizing` does the overwrite in its `Drop`, so removing it from the map is
/// the erase. Returns whether there was anything to forget, which is what lets
/// the window tell "the hold ended" from "that token was never real".
pub fn forget(mark: &str) -> bool {
    let mut map = store().lock().unwrap_or_else(|e| e.into_inner());
    sweep(&mut map);
    map.remove(mark).is_some()
}

/// Forget everything. The window locking, signing out or closing.
pub fn forget_all() {
    let mut map = store().lock().unwrap_or_else(|e| e.into_inner());
    map.clear();
}

/// The picture for a token, or nothing if the hold has ended.
pub fn picture(mark: &str) -> Option<Vec<u8>> {
    let mut map = store().lock().unwrap_or_else(|e| e.into_inner());
    sweep(&mut map);
    map.get(mark).map(|held| held.picture.clone())
}

// ── the picture ────────────────────────────────────────────────────────────

/// The monospace face this machine already uses, found by path.
///
/// Not bundled. The icon set in the page is drawn by hand for the same reason
/// this is not a shipped font file: a third-party face is a second asset to
/// sign and a licence this repo would then have to carry. Reading the system's
/// own means the picture matches the `ui-monospace` the rest of the window asks
/// CSS for, on a machine that already has a licence for it.
///
/// `.ttc` collections are skipped deliberately — Menlo is one, and a collection
/// needs a parser this does not have. Every platform below ships at least one
/// plain `.ttf` monospace, and a machine that somehow has none fails closed:
/// the reveal is refused with a reason, rather than falling back to putting the
/// string in the window after all.
#[cfg(target_os = "macos")]
const FACES: &[&str] = &[
    "/System/Library/Fonts/SFNSMono.ttf",
    "/System/Library/Fonts/Monaco.ttf",
    "/System/Library/Fonts/Supplemental/Courier New.ttf",
];

#[cfg(target_os = "windows")]
const FACES: &[&str] = &[
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\lucon.ttf",
    r"C:\Windows\Fonts\cour.ttf",
];

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const FACES: &[&str] = &[
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
];

fn face() -> Option<&'static fontdue::Font> {
    static FACE: OnceLock<Option<fontdue::Font>> = OnceLock::new();
    FACE.get_or_init(|| {
        for path in FACES {
            let Ok(bytes) = std::fs::read(path) else { continue };
            if let Ok(font) = fontdue::Font::from_bytes(bytes, fontdue::FontSettings::default()) {
                return Some(font);
            }
        }
        None
    })
    .as_ref()
}

/// Whether this machine can draw a credential at all.
pub fn can_draw() -> bool {
    face().is_some()
}

/// `rrggbb` as three bytes, or nothing.
///
/// The window reads its own computed `--ink1` and passes it down, so the
/// picture matches the theme the person is actually looking at rather than a
/// colour guessed on this side.
pub fn hex_ink(raw: &str) -> Option<[u8; 3]> {
    let raw = raw.trim().trim_start_matches("%23").trim_start_matches('#');
    if raw.len() != 6 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |at: usize| u8::from_str_radix(&raw[at..at + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

/// Where a brokered draw puts its PNG on the way back.
///
/// In this user's own runtime directory rather than a shared `/tmp`: the file
/// holds a picture of a credential for the few milliseconds between the child
/// writing it and the parent unlinking it, and a world-readable directory would
/// make that window worth waiting for. The name carries randomness so two
/// reveals in flight cannot collide, and the key name is not in it.
pub fn scratch_path(_key: &str) -> Result<std::path::PathBuf, String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| "the OS has no randomness".to_string())?;
    let stem: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
    let dir = std::env::temp_dir().join("passbook-veil");
    std::fs::create_dir_all(&dir).map_err(|error| format!("no scratch directory: {error}"))?;
    tighten(&dir)?;
    Ok(dir.join(format!("{stem}.png")))
}

/// 0700 on the directory, 0600 on the file. A no-op on Windows, where the
/// per-user temp directory is already inaccessible to other users.
fn tighten(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("could not tighten {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write bytes nobody else can read, creating the file with those permissions
/// rather than fixing them afterwards.
pub fn write_private(path: &str, bytes: &[u8]) -> Result<(), String> {
    let path = std::path::Path::new(path);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(path)
            .map_err(|error| format!("could not write the picture: {error}"))?;
        return file.write_all(bytes)
            .map_err(|error| format!("could not write the picture: {error}"));
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
            .map_err(|error| format!("could not write the picture: {error}"))?;
        tighten(path)
    }
}

/// What the window asks for: one line, at a size and colour it chose.
pub struct Ask {
    pub px: f32,
    pub scale: f32,
    pub ink: [u8; 3],
}

/// Draw one line of text as RGBA, and hand back a PNG.
///
/// The ink is flat and the coverage is the alpha, so the same picture sits on
/// the light theme and the dark one without a second render, and without the
/// halo a pre-composited background would leave over a rounded row.
pub fn draw(text: &str, ask: &Ask) -> Result<Vec<u8>, String> {
    let font = face().ok_or("This machine has no monospace font PassBook can draw with.")?;
    let px = (ask.px * ask.scale).clamp(4.0, 200.0);
    let chars: Vec<char> = text.chars().take(MAX_CHARS).collect();

    let line = font.horizontal_line_metrics(px)
        .ok_or("That font has no horizontal metrics.")?;
    let height = (line.ascent - line.descent).ceil().max(1.0) as usize;
    let baseline = line.ascent.ceil().max(0.0) as usize;

    // Measured before anything is allocated, so a pathological value is refused
    // rather than served after this process has already grown by its size.
    let width = chars.iter()
        .map(|&ch| font.metrics(ch, px).advance_width)
        .sum::<f32>()
        .ceil()
        .max(1.0) as usize;
    if width.saturating_mul(height) > MAX_PIXELS {
        return Err("That value is too long to draw.".into());
    }

    let mut rgba = vec![0u8; width * height * 4];
    let mut pen = 0.0f32;
    for &ch in &chars {
        let (metrics, coverage) = font.rasterize(ch, px);
        // fontdue hands back the glyph's own box and where it sits relative to
        // the pen and the baseline; ymin is measured up from the baseline, so a
        // descender is negative and the top edge is the baseline minus height
        // minus ymin.
        let left = (pen + metrics.xmin as f32).round() as isize;
        let top = baseline as isize - metrics.ymin as isize - metrics.height as isize;
        for row in 0..metrics.height {
            let y = top + row as isize;
            if y < 0 || y as usize >= height {
                continue;
            }
            for column in 0..metrics.width {
                let x = left + column as isize;
                if x < 0 || x as usize >= width {
                    continue;
                }
                let alpha = coverage[row * metrics.width + column];
                if alpha == 0 {
                    continue;
                }
                let at = ((y as usize) * width + x as usize) * 4;
                // Glyphs in a monospace line do not overlap, but a font with
                // kerning built into its advances can put them a pixel apart;
                // keeping the darker of the two is cheaper than blending and
                // indistinguishable at this size.
                if alpha > rgba[at + 3] {
                    rgba[at] = ask.ink[0];
                    rgba[at + 1] = ask.ink[1];
                    rgba[at + 2] = ask.ink[2];
                    rgba[at + 3] = alpha;
                }
            }
        }
        pen += metrics.advance_width;
    }

    encode(&rgba, width as u32, height as u32)
}

fn encode(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
        writer.write_image_data(rgba).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask() -> Ask {
        Ask { px: 12.0, scale: 2.0, ink: [0x11, 0x22, 0x33] }
    }

    // Nothing in here calls `forget_all`. These share a process — and therefore
    // this store — with the server tests in main.rs, and a test that wiped
    // everything failed a test that was holding a token at the time. Each one
    // cleans up the tokens it made and no others.

    const VALUE: &str = "sk-ant-api03-EXAMPLE-0123456789";

    fn drawn() -> Vec<u8> {
        draw(VALUE, &ask()).expect("drawn")
    }

    #[test]
    fn a_token_is_not_the_value_and_not_another_token() {
        if !can_draw() { return }
        let first = hold(drawn());
        let second = hold(drawn());
        assert_ne!(first, second, "the same value must not produce the same token");
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        forget(&first);
        forget(&second);
    }

    #[test]
    fn forgetting_is_idempotent_and_reported() {
        let mark = hold(vec![1, 2, 3]);
        assert!(picture(&mark).is_some(), "it was held");
        assert!(forget(&mark), "the first forget had something to forget");
        assert!(!forget(&mark), "the second did not");
        assert!(picture(&mark).is_none(), "and it is gone");
    }

    #[test]
    fn an_unknown_token_gets_nothing() {
        assert!(picture("00").is_none());
    }

    #[test]
    fn what_is_held_is_a_picture_and_not_the_value() {
        if !can_draw() { return }
        let mark = hold(drawn());
        let png = picture(&mark).expect("held");
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "that is not a PNG");
        // The whole point: nothing downstream of the token can recover the text.
        assert!(!png.windows(7).any(|w| w == b"sk-ant-"));
        assert!(!png.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
        forget(&mark);
    }

    #[test]
    fn a_longer_value_draws_a_wider_picture() {
        if !can_draw() { return }
        let short = draw("aa", &ask()).expect("drawn");
        let long = draw("aaaaaaaaaaaaaaaa", &ask()).expect("drawn");
        assert!(long.len() > short.len(), "sixteen glyphs should outweigh two");
    }

    #[test]
    fn an_absurd_value_is_refused_rather_than_allocated() {
        if !can_draw() { return }
        let huge = "M".repeat(MAX_CHARS * 2);
        match draw(&huge, &Ask { px: 200.0, scale: 1.0, ink: [0, 0, 0] }) {
            Err(why) => assert!(why.contains("too long")),
            Ok(png) => assert!(png.len() < 40_000_000),
        }
    }

    #[test]
    fn the_ink_is_the_colour_that_was_asked_for() {
        if !can_draw() { return }
        let png = draw("W", &Ask { px: 40.0, scale: 1.0, ink: [0xde, 0xad, 0xbe] }).expect("drawn");
        let decoder = png::Decoder::new(std::io::Cursor::new(&png));
        let mut reader = decoder.read_info().expect("readable");
        let mut buf = vec![0; reader.output_buffer_size().expect("sized")];
        let info = reader.next_frame(&mut buf).expect("a frame");
        let pixels = &buf[..info.buffer_size()];
        let inked = pixels.chunks_exact(4).find(|p| p[3] > 0).expect("some ink");
        assert_eq!([inked[0], inked[1], inked[2]], [0xde, 0xad, 0xbe]);
    }

    #[test]
    fn ink_is_read_the_way_the_window_writes_it() {
        assert_eq!(hex_ink("f2f3f5"), Some([0xf2, 0xf3, 0xf5]));
        assert_eq!(hex_ink("#16171a"), Some([0x16, 0x17, 0x1a]));
        assert_eq!(hex_ink("%2316171a"), Some([0x16, 0x17, 0x1a]));
        // Anything else falls back rather than half-parsing into a wrong colour.
        assert_eq!(hex_ink("nope"), None);
        assert_eq!(hex_ink("f2f3f"), None);
        assert_eq!(hex_ink("zzzzzz"), None);
    }

    /// The picture goes to disk for the few milliseconds between a brokered
    /// child writing it and the parent unlinking it. Nobody else may read it.
    #[test]
    fn the_scratch_file_is_private() {
        let path = scratch_path("ANY_KEY").expect("a path");
        write_private(&path.to_string_lossy(), b"pretend png").expect("written");
        assert!(!path.to_string_lossy().contains("ANY_KEY"),
                "the key name must not be in a world-listable path");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = std::fs::metadata(&path).expect("there").permissions().mode() & 0o777;
            let dir = std::fs::metadata(path.parent().unwrap()).expect("there")
                .permissions().mode() & 0o777;
            assert_eq!(file, 0o600, "the picture is readable by somebody else");
            assert_eq!(dir, 0o700, "the directory is listable by somebody else");
        }
        std::fs::remove_file(&path).ok();
    }
}

#[cfg(test)]
mod look {
    use super::*;

    /// Not an assertion — a way to look at what this actually draws.
    ///
    /// `cargo test -- --ignored look_at_it` writes the PNGs somewhere they can
    /// be opened. Baseline, clipping and blur are the kind of thing a test
    /// asserting "it is a PNG" will happily pass while the picture is garbage.
    #[test]
    #[ignore]
    fn look_at_it() {
        let out = std::env::var("VEIL_LOOK").unwrap_or_else(|_| "/tmp".into());
        for (name, text, ink) in [
            ("light", "sk-veil-test-0123456789abcdef", [0x16, 0x17, 0x1a]),
            ("dark", "sk-veil-test-0123456789abcdef", [0xf2, 0xf3, 0xf5]),
            ("mixed", "gAAAAABo_-Wq/+=&?xyz{}[]|~^ 019 Il1O0", [0x16, 0x17, 0x1a]),
        ] {
            let png = draw(text, &Ask { px: 12.0, scale: 2.0, ink }).expect("drawn");
            std::fs::write(format!("{out}/veil-{name}.png"), png).expect("written");
        }
        eprintln!("wrote veil-*.png to {out}");
    }
}
