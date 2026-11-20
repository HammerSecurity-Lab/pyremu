//! 指纹载荷: 由灰度图像提取细节点并计算 BOZORTH3 匹配分.
//!
//! 子命令:
//!
//! - `match <probe.xyt> <gallery.xyt>`: 两个细节点文本文件直接比对;
//! - `image <probe.pgm> <gallery.pgm> [ppi]`: 两个 P5 灰度图像分别提取细节点后比对;
//! - `selftest`: 以内置细节点自检.

use std::fs;
use std::process::ExitCode;

use fprint_bozorth3 as bozorth3;
use fprint_mindtct::{GrayImage, detect_minutiae};

/// 默认扫描分辨率, 单位 PPI.
const DEFAULT_PPI: u16 = 500;

fn main() -> ExitCode {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let result = match args.first().map(String::as_str) {
		Some("match") if args.len() == 3 => cmd_match(&args[1], &args[2]),
		Some("image") if args.len() == 3 || args.len() == 4 => {
			let ppi = args
				.get(3)
				.map_or(DEFAULT_PPI, |s| s.parse().unwrap_or(DEFAULT_PPI));
			cmd_image(&args[1], &args[2], ppi)
		}
		Some("selftest") if args.len() == 1 => cmd_selftest(),
		_ => {
			eprintln!(
				"usage: fingerprint match <probe.xyt> <gallery.xyt>\n\
                 \x20      fingerprint image <probe.pgm> <gallery.pgm> [ppi]\n\
                 \x20      fingerprint selftest"
			);
			return ExitCode::from(2);
		}
	};
	match result {
		Ok(()) => ExitCode::SUCCESS,
		Err(message) => {
			eprintln!("fingerprint: {message}");
			ExitCode::FAILURE
		}
	}
}

fn cmd_match(probe_path: &str, gallery_path: &str) -> Result<(), String> {
	let probe = read_xyt(probe_path)?;
	let gallery = read_xyt(gallery_path)?;
	print_score(&probe, &gallery);
	Ok(())
}

fn cmd_image(probe_path: &str, gallery_path: &str, ppi: u16) -> Result<(), String> {
	let probe = read_image_minutiae(probe_path, ppi)?;
	let gallery = read_image_minutiae(gallery_path, ppi)?;
	println!("minutiae probe={} gallery={}", probe.len(), gallery.len());
	print_score(&probe, &gallery);
	Ok(())
}

fn cmd_selftest() -> Result<(), String> {
	let print: Vec<bozorth3::Minutia> = (0..12)
		.map(|i| {
			bozorth3::Minutia::from_xyt(
				20 + i * 9,
				30 + (i * 17) % 40,
				(i * 30) % 360,
			)
		})
		.collect();
	let score = bozorth3::match_score(&print, &print);
	println!("score={score}");
	if score == 0 {
		return Err("self-test score is zero".to_string());
	}
	Ok(())
}

fn print_score(probe: &[bozorth3::Minutia], gallery: &[bozorth3::Minutia]) {
	println!(
		"score={} probe={} gallery={}",
		bozorth3::match_score(probe, gallery),
		probe.len(),
		gallery.len()
	);
}

/// 每行取前三个整数 `x y theta`; 空行与 `#` 开头的行忽略.
fn read_xyt(path: &str) -> Result<Vec<bozorth3::Minutia>, String> {
	let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
	let mut minutiae = Vec::new();
	for (index, line) in text.lines().enumerate() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 3 {
			return Err(format!("{path}:{}: expected x y theta", index + 1));
		}
		let x = parse_field(path, index, fields[0])?;
		let y = parse_field(path, index, fields[1])?;
		let theta = parse_field(path, index, fields[2])?;
		minutiae.push(bozorth3::Minutia::from_xyt(x, y, theta));
	}
	Ok(minutiae)
}

fn parse_field(path: &str, index: usize, text: &str) -> Result<i32, String> {
	text.parse()
		.map_err(|_| format!("{path}:{}: invalid integer {text}", index + 1))
}

/// 读取 P5 灰度图像并提取细节点.
fn read_image_minutiae(
	path: &str,
	ppi: u16,
) -> Result<Vec<bozorth3::Minutia>, String> {
	let data = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
	let (pixels, width, height) =
		parse_pgm(&data).map_err(|e| format!("{path}: {e}"))?;
	let image = GrayImage::new(&pixels, width, height, ppi)
		.map_err(|e| format!("{path}: {e:?}"))?;
	Ok(detect_minutiae(image)
		.into_iter()
		.map(|m| bozorth3::Minutia::from_xyt(m.x, m.y, m.theta))
		.collect())
}

/// 解析 P5 灰度图像, 返回像素, 宽度与高度; 仅接受 8 位样本.
fn parse_pgm(data: &[u8]) -> Result<(Vec<u8>, usize, usize), String> {
	let mut pos = 0;
	expect_token(data, &mut pos, b"P5")?;
	let width = next_number(data, &mut pos)? as usize;
	let height = next_number(data, &mut pos)? as usize;
	let maxval = next_number(data, &mut pos)?;
	if maxval != 255 {
		return Err(format!("maxval {maxval} is not 255"));
	}
	if pos >= data.len() || !data[pos].is_ascii_whitespace() {
		return Err("missing whitespace after header".to_string());
	}
	pos += 1;
	let count = width * height;
	if data.len() < pos + count {
		return Err(format!(
			"short pixel data: need {count} bytes, got {}",
			data.len() - pos
		));
	}
	Ok((data[pos..pos + count].to_vec(), width, height))
}

fn next_number(data: &[u8], pos: &mut usize) -> Result<u32, String> {
	take_tokens(data, pos);
	let start = *pos;
	while *pos < data.len() && data[*pos].is_ascii_digit() {
		*pos += 1;
	}
	if start == *pos {
		return Err("missing number in header".to_string());
	}
	let text = std::str::from_utf8(&data[start..*pos]).map_err(|e| e.to_string())?;
	text.parse().map_err(|_| format!("invalid number {text}"))
}

fn expect_token(data: &[u8], pos: &mut usize, token: &[u8]) -> Result<(), String> {
	take_tokens(data, pos);
	if data[*pos..].starts_with(token) {
		*pos += token.len();
		Ok(())
	} else {
		Err("not a P5 grayscale image".to_string())
	}
}

fn take_tokens(data: &[u8], pos: &mut usize) {
	while *pos < data.len() {
		if data[*pos].is_ascii_whitespace() {
			*pos += 1;
		} else if data[*pos] == b'#' {
			while *pos < data.len() && data[*pos] != b'\n' {
				*pos += 1;
			}
		} else {
			break;
		}
	}
}
