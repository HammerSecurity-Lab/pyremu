//! 字节分类辅助.

/// 判定一个字节是否属于可见文本.
///
/// 可打印 ASCII、制表、换行与回车属于可见文本; 零字节、其余控制字符与高位
/// 字节不属于可见文本.
#[inline]
#[allow(unused)]
pub(crate) fn is_text_byte(b: u8) -> bool {
	matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e)
}

/// 判定一个字节是否仍属于文本内容.
///
/// 可见文本之外, 零字节也按文本计, 使带结尾零字节的字符串写入不被报告.
#[inline]
#[allow(unused)]
pub(crate) fn is_text_value_byte(b: u8) -> bool {
	b == 0 || is_text_byte(b)
}
