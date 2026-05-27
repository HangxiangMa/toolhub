#!/usr/bin/env python3
"""
ToolHub MCP Server

Exposes camera/ISP debug tools as MCP commands for use with Claude Code,
QGenie, or any MCP-compatible AI client.

Usage (stdio, for Claude Code integration):
    python server.py

Add to .mcp.json or Claude settings:
    {
      "mcpServers": {
        "toolhub": {
          "command": "python3",
          "args": ["<path-to>/toolhub/server.py"]
        }
      }
    }
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

from isp_timing_diagram import (
    parse_log,
    validate_and_associate_events,
    generate_timing_diagram,
    generate_ascii_waveform,
    generate_html_timing,
)

mcp = FastMCP(
    "toolhub",
    version="0.1.0",
    instructions="Camera/ISP debug tool collection for Qualcomm CamX pipeline analysis",
)


@mcp.tool()
def isp_timing_diagram(
    logfile: str,
    mode: str = "detail",
    ctx: Optional[int] = None,
    link: Optional[str] = None,
    csid_path: Optional[str] = None,
    width: int = 130,
) -> str:
    """Parse camera kernel logs and generate ISP timing diagrams.

    Extracts ISP hardware events (SOF, EOF, RUP, EPOCH, BUF_DONE) from kernel
    logs and generates text-based timing diagrams grouped by pipeline (ctx + link).

    Supports both logcat and ftrace log formats.

    Args:
        logfile: Path to the kernel log file (logcat or ftrace format).
        mode: Output mode - "detail" for event list, "waveform" for ASCII lanes,
              "both" for combined output, "html" for interactive HTML.
        ctx: Filter by context index (e.g. 3). None means all contexts.
        link: Filter by link handle (e.g. "0xa6031a"). None means all links.
        csid_path: Filter SOF/EOF by CSID path (e.g. "IPP_0", "IPP_1").
        width: Maximum output width in characters (default 130).

    Returns:
        The timing diagram as text (or HTML string if mode="html").
        For HTML mode, also writes the file to disk and returns the path.
    """
    log_path = Path(logfile).expanduser().resolve()
    if not log_path.exists():
        return f"Error: log file not found: {log_path}"

    events, ctx_ipp_paths = parse_log(
        str(log_path),
        ctx_filter=ctx,
        link_filter=link,
        csid_path_filter=csid_path,
    )

    if not events:
        return (
            "No ISP events found in the log file.\n"
            "Make sure the log contains CAM-ISP debug messages with "
            "CSID path_top_half or IRQ handler entries."
        )

    events = validate_and_associate_events(events)

    summary_lines = [f"Parsed {len(events)} events from: {log_path.name}"]
    for ctx_id, paths in sorted(ctx_ipp_paths.items()):
        if len(paths) > 1:
            summary_lines.append(
                f"  ctx={ctx_id}: {len(paths)}EXP (paths: {', '.join(sorted(paths))})"
            )
        else:
            summary_lines.append(
                f"  ctx={ctx_id}: 1EXP (path: {', '.join(sorted(paths))})"
            )

    orphan_eofs = [e for e in events if "!!ORPHAN_EOF!!" in e.extra]
    missing_eofs = [e for e in events if "!!MISSING_EOF!!" in e.extra]
    if orphan_eofs:
        summary_lines.append(f"  WARNING: {len(orphan_eofs)} EOF(s) without prior SOF")
    if missing_eofs:
        summary_lines.append(f"  WARNING: {len(missing_eofs)} SOF(s) without subsequent EOF")

    summary = "\n".join(summary_lines)

    if mode == "html":
        html_content = generate_html_timing(
            events, max_width=width, ctx_ipp_paths=ctx_ipp_paths
        )
        out_path = log_path.with_suffix("").with_suffix(".timing.html")
        out_path.write_text(html_content, encoding="utf-8")
        return f"{summary}\n\nHTML timing diagram written to: {out_path}"

    output = ""
    if mode in ("detail", "both"):
        output += generate_timing_diagram(events, use_color=False, max_width=width)
    if mode in ("waveform", "both"):
        if output:
            output += "\n\n"
        output += generate_ascii_waveform(events, use_color=False, max_width=width)

    return f"{summary}\n\n{output}"


if __name__ == "__main__":
    mcp.run(transport="stdio", show_banner=False)
