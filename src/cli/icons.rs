//! Extraction and caching of Windows executable icons for display in the GUI.
//!
//! Icons are keyed by process name. The first time a name is seen, the module
//! resolves the executable path of one of its PIDs, pulls the shell icon out of
//! that file, and uploads it to the GPU as an egui texture.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;

use eframe::egui;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Graphics::Gdi::{BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC, GetDIBits, GetObjectW, HBITMAP, HDC, ReleaseDC};
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGetFileInfoW};
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};
use windows::core::{PCWSTR, PWSTR};

/// Number of times we retry an icon lookup before we give up on a process name.
const MAX_ATTEMPTS: u8 = 3;

struct IconEntry {
	texture: Option<egui::TextureHandle>,
	attempts: u8,
}

/// Cache of process-name -> icon texture.
#[derive(Default)]
pub struct IconCache {
	entries: HashMap<String, IconEntry>,
}

impl IconCache {
	pub fn new() -> Self {
		Self::default()
	}

	/// Returns the icon texture for `name`, loading it from the executable of
	/// `pid` on the first call. Returns `None` if the icon is not available.
	pub fn get(&mut self, ctx: &egui::Context, name: &str, pid: u32) -> Option<egui::TextureHandle> {
		if let Some(entry) = self.entries.get(name) {
			if entry.texture.is_some() || entry.attempts >= MAX_ATTEMPTS {
				return entry.texture.clone();
			}
		}

		let texture = exe_path(pid).and_then(|path| icon_rgba(&path)).map(|(rgba, width, height)| {
			let image = egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &rgba);
			ctx.load_texture(format!("icon::{name}"), image, egui::TextureOptions::LINEAR)
		});

		let entry = self.entries.entry(name.to_string()).or_insert(IconEntry { texture: None, attempts: 0 });
		entry.attempts = entry.attempts.saturating_add(1);
		if texture.is_some() {
			entry.texture = texture;
		}
		entry.texture.clone()
	}
}

/// Returns the full path of the executable behind `pid`.
pub fn exe_path(pid: u32) -> Option<String> {
	if pid == 0 {
		return None;
	}

	unsafe {
		let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

		let mut buffer = [0u16; 32768];
		let mut length = buffer.len() as u32;
		let result = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut length);
		CloseHandle(handle).ok();

		result.ok()?;
		Some(String::from_utf16_lossy(&buffer[..length as usize]))
	}
}

/// Reads the shell icon of a file and returns it as `(rgba, width, height)`.
fn icon_rgba(path: &str) -> Option<(Vec<u8>, u32, u32)> {
	let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

	unsafe {
		let mut info = SHFILEINFOW::default();
		let result = SHGetFileInfoW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(0), Some(&mut info), size_of::<SHFILEINFOW>() as u32, SHGFI_ICON | SHGFI_LARGEICON);

		if result == 0 || info.hIcon.is_invalid() {
			return None;
		}

		let rgba = hicon_rgba(info.hIcon);
		DestroyIcon(info.hIcon).ok();
		rgba
	}
}

/// Converts an `HICON` into a top-down RGBA buffer.
unsafe fn hicon_rgba(icon: HICON) -> Option<(Vec<u8>, u32, u32)> {
	unsafe {
		let mut icon_info = ICONINFO::default();
		GetIconInfo(icon, &mut icon_info).ok()?;

		let color = icon_info.hbmColor;
		let mask = icon_info.hbmMask;

		let result = (|| {
			if color.is_invalid() {
				return None;
			}

			let mut bitmap = BITMAP::default();
			if GetObjectW(color.into(), size_of::<BITMAP>() as i32, Some(&mut bitmap as *mut _ as *mut c_void)) == 0 {
				return None;
			}

			let width = bitmap.bmWidth.max(0) as u32;
			let height = bitmap.bmHeight.max(0) as u32;
			if width == 0 || height == 0 {
				return None;
			}

			let dc = GetDC(None);
			if dc.is_invalid() {
				return None;
			}

			let mut pixels = read_bitmap(dc, color, width, height);
			if pixels.is_some() && !mask.is_invalid() {
				apply_mask(dc, mask, width, height, pixels.as_mut().unwrap());
			}
			ReleaseDC(None, dc);

			pixels.map(|p| (p, width, height))
		})();

		if !color.is_invalid() {
			let _ = DeleteObject(color.into());
		}
		if !mask.is_invalid() {
			let _ = DeleteObject(mask.into());
		}

		result
	}
}

/// Reads a device-independent 32-bit copy of `bitmap` and converts BGRA to RGBA.
unsafe fn read_bitmap(dc: HDC, bitmap: HBITMAP, width: u32, height: u32) -> Option<Vec<u8>> {
	unsafe {
		let mut info: BITMAPINFO = std::mem::zeroed();
		info.bmiHeader = BITMAPINFOHEADER {
			biSize: size_of::<BITMAPINFOHEADER>() as u32,
			biWidth: width as i32,
			// A negative height asks GDI for a top-down image, which is the
			// order egui expects.
			biHeight: -(height as i32),
			biPlanes: 1,
			biBitCount: 32,
			biCompression: BI_RGB.0,
			..Default::default()
		};

		let mut buffer = vec![0u8; (width * height * 4) as usize];
		let lines = GetDIBits(dc, bitmap, 0, height, Some(buffer.as_mut_ptr() as *mut c_void), &mut info, DIB_RGB_COLORS);

		if lines == 0 {
			return None;
		}

		for pixel in buffer.chunks_exact_mut(4) {
			pixel.swap(0, 2);
		}

		Some(buffer)
	}
}

/// Older icons carry no alpha channel. For those, the AND mask says which
/// pixels are transparent: a set mask bit means "show the background".
unsafe fn apply_mask(dc: HDC, mask: HBITMAP, width: u32, height: u32, pixels: &mut [u8]) {
	unsafe {
		if pixels.chunks_exact(4).any(|p| p[3] != 0) {
			return;
		}

		let Some(mask_pixels) = read_bitmap(dc, mask, width, height) else {
			// Without a usable mask the icon is fully opaque.
			for pixel in pixels.chunks_exact_mut(4) {
				pixel[3] = 255;
			}
			return;
		};

		for (pixel, mask_pixel) in pixels.chunks_exact_mut(4).zip(mask_pixels.chunks_exact(4)) {
			pixel[3] = if mask_pixel[0] == 0 { 255 } else { 0 };
		}
	}
}
