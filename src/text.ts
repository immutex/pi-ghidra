// Text helpers shared by the extension and the MCP server. Both hosts cap
// tool output, and cutting a UTF-8 buffer at an arbitrary byte offset would
// produce a replacement character in the middle of the result.

export interface HeadTruncation {
	content: string;
	truncated: boolean;
	outputBytes: number;
	totalBytes: number;
	outputLines: number;
	totalLines: number;
}

export function truncateUtf8(
	text: string,
	maxBytes: number,
): { text: string; truncated: boolean } {
	const buffer = Buffer.from(text, "utf8");
	if (buffer.length <= maxBytes) return { text, truncated: false };
	let end = Math.max(0, maxBytes);
	// Back up to the leading byte of the character that straddles the cut.
	while (end > 0 && ((buffer[end] ?? 0) & 0xc0) === 0x80) end -= 1;
	return {
		text: buffer.subarray(0, end).toString("utf8"),
		truncated: true,
	};
}

export function truncateHead(
	text: string,
	maxBytes: number,
	maxLines: number,
): HeadTruncation {
	const lines = text.split("\n");
	const totalBytes = Buffer.byteLength(text, "utf8");
	const totalLines = lines.length;
	const kept: string[] = [];
	let outputBytes = 0;
	for (const line of lines) {
		if (kept.length >= maxLines) break;
		const lineBytes = Buffer.byteLength(line, "utf8");
		const separatorBytes = kept.length === 0 ? 0 : 1;
		if (outputBytes + separatorBytes + lineBytes > maxBytes) break;
		kept.push(line);
		outputBytes += separatorBytes + lineBytes;
	}
	if (kept.length === totalLines) {
		return {
			content: text,
			truncated: false,
			outputBytes: totalBytes,
			totalBytes,
			outputLines: totalLines,
			totalLines,
		};
	}
	// A single line can exceed the byte budget; fall back to a byte cut.
	const content = kept.length
		? kept.join("\n")
		: truncateUtf8(text, maxBytes).text;
	const bytes = Buffer.byteLength(content, "utf8");
	return {
		content,
		truncated: true,
		outputBytes: bytes,
		totalBytes,
		outputLines: kept.length || 1,
		totalLines,
	};
}
