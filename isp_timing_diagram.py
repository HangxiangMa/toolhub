#!/usr/bin/env python3
"""
ISP Timing Diagram Generator

Parses camera kernel logs to extract ISP hardware events (SOF, EOF, RUP, EPOCH, BUF_DONE)
and generates a text-based timing diagram grouped by pipeline (ctx + link).

Event detection is based on the kernel source:
  - SOF:      cam_ife_csid_ver2_path_top_half status: 0x1000
  - EOF:      cam_ife_csid_ver2_path_top_half status: 0x200
  - RUP:      cam_isp_hw_event_type = 2 (REG_UPDATE), or Handle CSID REG_UPDATE
  - EPOCH:    cam_isp_hw_event_type = 3, or Handle CSID EPOCH
  - BUF_DONE: cam_isp_hw_event_type = 5, or Handle IFE BUF_DONE
"""

import re
import sys
import math
import argparse
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional


# Symbols for each event type
EVENT_SYMBOLS = {
    'SOF':      '▼',   # frame start
    'EOF':      '▲',   # frame end
    'RUP':      '■',   # register update
    'EPOCH0':   '●',   # epoch0
    'EPOCH1':   '○',   # epoch1
    'BUF_DONE': '★',   # buffer done
}

EVENT_COLORS = {
    'SOF':      '\033[92m',  # green
    'EOF':      '\033[91m',  # red
    'RUP':      '\033[94m',  # blue
    'EPOCH0':   '\033[93m',  # yellow
    'EPOCH1':   '\033[33m',  # dark yellow
    'BUF_DONE': '\033[95m',  # magenta
}
RESET_COLOR = '\033[0m'


@dataclass
class Event:
    timestamp: str       # MM-DD HH:MM:SS.mmm
    ts_ms: float         # timestamp in ms for sorting
    event_type: str      # SOF, EOF, RUP, EPOCH, BUF_DONE
    ctx: int             # context index
    link: str            # link handle (hex string)
    frame_id: int = -1   # frame id if available
    req_id: int = -1     # request id if available
    csid: int = -1       # CSID index
    extra: str = ''      # additional info
    line_no: int = 0     # line number in log for stable ordering
    paired_sof: object = None   # For EOF: back-reference to its paired SOF event
    paired_eof: object = None   # For SOF: forward-reference to its paired EOF event
    assoc_rup: object = None    # For SOF: the RUP (or EPOCH) this SOF belongs to


def parse_timestamp_ms(ts_str: str) -> float:
    """Convert MM-DD HH:MM:SS.mmm to milliseconds from start of day."""
    m = re.match(r'(\d+)-(\d+)\s+(\d+):(\d+):(\d+)\.(\d+)', ts_str)
    if not m:
        return 0.0
    month, day, hour, minute, sec, msec = [int(x) for x in m.groups()]
    return ((day * 24 + hour) * 3600 + minute * 60 + sec) * 1000.0 + msec


def parse_log(filepath: str, ctx_filter: Optional[int] = None,
              link_filter: Optional[str] = None,
              csid_path_filter: Optional[str] = None) -> Tuple[List[Event], Dict[int, set]]:
    """Parse log file and extract ISP events.
    Returns: (events, ctx_ipp_paths) where ctx_ipp_paths maps ctx_id to
    set of IPP paths (e.g. {"IPP_0", "IPP_1"} for 2EXP).
    """
    events = []

    # Regex for standard log line timestamp (logcat: "05-03 03:52:18.797")
    ts_re = re.compile(r'^(\d+-\d+\s+\d+:\d+:\d+\.\d+)')
    # Regex for ftrace timestamp (e.g., "   600.205916:" — boot seconds.us)
    ts_re_ftrace = re.compile(r'\s(\d+\.\d{6}):\s')

    def _line_ts(line):
        m = ts_re.match(line)
        if m:
            ts_str = m.group(1)
            return ts_str, parse_timestamp_ms(ts_str)
        m = ts_re_ftrace.search(line)
        if m:
            sec_str = m.group(1)
            return sec_str, float(sec_str) * 1000.0
        return None, None

    # Pattern: CSID path IRQ status with hardware timestamp (preferred, more accurate)
    # Log format:
    #   "cam_ife_csid_ver2_parse_path_irq_status: 3118: CSID[1] IRQ IPP1 INFO_INPUT_SOF timestamp: [602:967443206]"
    #   "cam_ife_csid_ver2_parse_path_irq_status: 3118: CSID[1] IRQ IPP1 INFO_INPUT_EOF timestamp: [602:977396487]"
    #   "cam_ife_csid_ver2_parse_path_irq_status: 3118: CSID[1] IRQ IPP CAMIF_EPOCH0 timestamp: [602:970000000]"
    #   "cam_ife_csid_ver2_parse_path_irq_status: 3118: CSID[1] IRQ IPP CAMIF_EPOCH1 timestamp: [602:975000000]"
    csid_irq_status_re = re.compile(
        r'cam_ife_csid_ver2_parse_path_irq_status.*?CSID\[(\d+)\]\s+IRQ\s+(\w+)\s+(?:INFO_INPUT_(SOF|EOF)|CAMIF_(EPOCH0|EPOCH1))\s+timestamp:\s*\[(\d+):(\d+)\]')

    # Pattern: CSID path top half status (SOF/EOF from CSID IRQ) - legacy fallback
    # Log format examples:
    #   "CSID:2 IPP status: 0x1000"   -> CSID 2, IPP_0
    #   "CSID:2 IPP1 status: 0x1000"  -> CSID 2, IPP_1
    #   "CSID:2 RDI0 status: 0x1000"  -> CSID 2, RDI_0
    #   "CSID:1 IPP status: 0x200"    -> CSID 1, IPP_0
    csid_status_re = re.compile(
        r'cam_ife_csid_ver2_path_top_half.*?CSID:(\d+)\s+(\w+?)\s+status:\s*(0x[0-9a-fA-F]+)')

    # Pattern: Handle CSID event (REG_UPDATE/EPOCH) - has ctx directly
    # "cam_ife_hw_mgr_handle_csid_event: 18706: Handle CSID[2] REG_UPDATE event in ctx: 3"
    csid_event_re = re.compile(
        r'Handle CSID\[(\d+)\]\s+(REG_UPDATE|EPOCH)\s+event\s+in\s+ctx:\s*(\d+)')

    # Pattern: Handle IFE event (BUF_DONE) - fallback when tracepoint not available
    # "cam_ife_hw_mgr_handle_ife_event: 18653: Handle IFE[2] BUF_DONE event in ctx: 3"
    ife_event_re = re.compile(
        r'Handle IFE\[(\d+)\]\s+(BUF_DONE)\s+event\s+in\s+ctx:\s*(\d+)')

    # Pattern: cam_buf_done tracepoint (authoritative BUF_DONE source with link/request)
    # "binder:1593_5-7472  [001] .Ns1.  158.535761: cam_buf_done:   ISP: BufDone ctx=0000000067c2cf7a request=51 link_hdl=0x4f0321"
    cam_buf_done_re = re.compile(
        r'cam_buf_done:.*?BufDone\s+ctx=\w+\s+request=(\d+)\s+link_hdl=(0x[0-9a-fA-F]+)')

    # Pattern: IRQ handler with evt_id, ctx, link
    # "__cam_isp_ctx_handle_irq_in_activated: ... evt id 2, ctx:3 link: 0xa6031a"
    irq_handler_re = re.compile(
        r'__cam_isp_ctx_handle_irq_in_activated.*?evt\s+id\s+(\d+),\s*ctx:(\d+)\s+link:\s*(0x[0-9a-fA-F]+)')

    # Pattern: SOF timestamp update with frame_id, ctx, link
    # "__cam_isp_ctx_update_sof_ts: ... Frame id: 3, ... ctx 3, request id: 1, link: 0xa6031a"
    sof_ts_re = re.compile(
        r'__cam_isp_ctx_update_sof_ts.*?Frame\s+id:\s*(\d+).*?ctx\s+(\d+).*?request\s+id:\s*(\d+).*?link:\s*(0x[0-9a-fA-F]+)')

    # Pattern: BUF_DONE context with req, ctx, link
    buf_done_ctx_re = re.compile(
        r'__cam_isp_ctx_handle_buf_done_for_request_verify_addr.*?Enter.*?ctx\s+(\d+),\s*link\[(0x[0-9a-fA-F]+)\]')

    # Pattern: CSID start hw - learn CSID+path -> ctx mapping
    # "cam_ife_mgr_csid_start_hw: 1747: csid[2] ctx_idx: 3 res:IPP_0 res_id 5 cnt 0"
    csid_start_re = re.compile(
        r'cam_ife_mgr_csid_start_hw.*?csid\[(\d+)\]\s+ctx_idx:\s*(\d+)\s+res:(IPP_\d+|RDI_\d+)')

    # Track current frame_id per (ctx, link)
    current_frame: Dict[Tuple[int, str], int] = {}
    # Track current req_id per (ctx, link)
    current_req: Dict[Tuple[int, str], int] = {}
    # Track the last emitted RUP event per (ctx, link) so update_sof_ts can
    # retroactively fix its frame/req (the RUP log line prints BEFORE
    # update_sof_ts in the same ISR, so it picks up stale values at parse time).
    last_rup_event: Dict[Tuple[int, str], Event] = {}
    # Track link per ctx from earlier context logs
    ctx_link_map: Dict[int, str] = {}
    # Reverse: link -> ctx (populated from trustworthy sources only)
    link_to_ctx: Dict[str, int] = {}
    # (req_id, link) -> ctx mapping learned from SOF timestamp logs.
    # Authoritative for resolving cam_buf_done tracepoints.
    req_link_to_ctx: Dict[Tuple[int, str], int] = {}
    # Track CSID+path -> ctx mapping (key: "csid:path", e.g. "2:IPP_0")
    csid_path_to_ctx: Dict[str, int] = {}
    # Track which CSID has multiple IPP paths for a given ctx (2EXP detection)
    # Key: ctx_id, Value: set of IPP paths on same CSID (e.g., {"IPP_0", "IPP_1"})
    ctx_ipp_paths: Dict[int, set] = defaultdict(set)
    # Track HW timestamps per (csid, path) for simultaneous SOF+EOF detection.
    # Key: (csid_idx, path_name), Value: list of (hw_ts_ms, evt_type) from same log line batch
    pending_hw_events: Dict[Tuple[int, str], List[Tuple[float, str]]] = defaultdict(list)
    # Last HW timestamp seen per (csid, path) — used to group events arriving together
    last_hw_ts_per_path: Dict[Tuple[int, str], float] = {}
    # Track which CSIDs have parse_path_irq_status logs (preferred over path_top_half).
    # Pre-scan the file to detect this before main parsing loop.
    # Also detect log format (ftrace vs logcat) and compute HW→line timestamp offset.
    csid_has_hw_ts: set = set()
    is_ftrace = False
    hw_to_line_offset: float = 0.0
    offset_samples: List[float] = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f_pre:
        for pre_line in f_pre:
            if not is_ftrace and ts_re_ftrace.search(pre_line):
                is_ftrace = True
            if 'parse_path_irq_status' in pre_line:
                m_pre = csid_irq_status_re.search(pre_line)
                if m_pre:
                    csid_has_hw_ts.add(int(m_pre.group(1)))
                    # Collect offset samples (line_ts - hw_ts)
                    if len(offset_samples) < 50:
                        pre_ts_str, pre_ts_ms = _line_ts(pre_line)
                        if pre_ts_ms is not None:
                            pre_hw_sec = int(m_pre.group(5))
                            pre_hw_nsec = int(m_pre.group(6))
                            pre_hw_ms = pre_hw_sec * 1000.0 + pre_hw_nsec / 1_000_000.0
                            offset_samples.append(pre_ts_ms - pre_hw_ms)
    # The HW event happens BEFORE the log line is printed (ISR + printk latency).
    # So (line_ts - hw_ts) >= true_offset. Use the minimum sample as best estimate.
    if offset_samples:
        hw_to_line_offset = min(offset_samples)

    # Pattern to learn ctx-link mapping
    ctx_link_re = re.compile(r'ctx[_:]?\s*(\d+).*?link[:\s]+\s*(0x[0-9a-fA-F]+)')

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_no, line in enumerate(f, 1):
            # Skip non-camera lines for performance
            if ('CAM' not in line and 'cam_ife' not in line
                    and 'cam_buf_done' not in line
                    and 'parse_path_irq_status' not in line):
                continue

            # Extract timestamp (supports both logcat and ftrace formats)
            timestamp, ts_ms = _line_ts(line)
            if timestamp is None:
                continue

            # Learn ctx-link mappings from any line
            cl_match = ctx_link_re.search(line)
            if cl_match:
                c = int(cl_match.group(1))
                l = cl_match.group(2).lower()
                if l != '0xffffffff':
                    ctx_link_map[c] = l

            # Learn CSID+path -> ctx mapping from csid_start_hw
            m = csid_start_re.search(line)
            if m:
                csid_idx = int(m.group(1))
                ctx_id = int(m.group(2))
                res_name = m.group(3)  # IPP_0, IPP_1, RDI_0, etc.
                csid_path_to_ctx[f"{csid_idx}:{res_name}"] = ctx_id
                if res_name.startswith('IPP'):
                    ctx_ipp_paths[ctx_id].add(res_name)
                continue

            # 0. CSID IRQ status with HW timestamp (preferred source for SOF/EOF/EPOCH)
            m = csid_irq_status_re.search(line)
            if m:
                csid_idx = int(m.group(1))
                path_raw = m.group(2)  # "IPP", "IPP1", "IPP2", "RDI0", etc.
                evt_type = m.group(3) or m.group(4)  # "SOF"/"EOF" or "EPOCH0"/"EPOCH1"
                hw_sec = int(m.group(5))
                hw_nsec = int(m.group(6))
                # Raw HW timestamp in boot-time ms
                hw_ts_raw = hw_sec * 1000.0 + hw_nsec / 1_000_000.0
                # Convert to the line-timestamp domain (identity for ftrace,
                # adds wall-clock offset for logcat).
                # The HW event happened BEFORE the log line was printed (ISR
                # latency), so hw_ts_ms <= ts_ms. This preserves the true
                # timing relationship between SOF/EOF and other events.
                hw_ts_ms = hw_ts_raw + hw_to_line_offset

                # Normalize path name
                if path_raw == 'IPP':
                    path_name = 'IPP_0'
                elif path_raw.startswith('IPP') and path_raw[3:].isdigit():
                    path_name = f'IPP_{path_raw[3:]}'
                elif path_raw.startswith('RDI') and path_raw[3:].isdigit():
                    path_name = f'RDI_{path_raw[3:]}'
                else:
                    continue

                if not path_name.startswith('IPP'):
                    continue

                if csid_path_filter and path_name != csid_path_filter:
                    continue

                csid_key = f"{csid_idx}:{path_name}"
                ctx_id = csid_path_to_ctx.get(csid_key)
                if ctx_id is None:
                    continue

                link = ctx_link_map.get(ctx_id)
                if link is None:
                    continue

                # Detect simultaneous SOF+EOF: check if another event for the same
                # (csid, path) arrived at a very close HW timestamp (within 1us).
                # Only applies to SOF/EOF, not EPOCH events.
                sof_eof_collision = False
                if evt_type in ('SOF', 'EOF'):
                    path_key = (csid_idx, path_name)
                    last_hw = last_hw_ts_per_path.get(path_key)
                    simultaneous = False
                    if last_hw is not None and abs(hw_ts_ms - last_hw) < 0.001:
                        simultaneous = True
                    last_hw_ts_per_path[path_key] = hw_ts_ms

                    # Also check: if we just saw the opposite event type at the exact
                    # same HW timestamp, that's a SOF+EOF collision error.
                    # Mark BOTH events (the earlier one already appended, and this one).
                    if simultaneous:
                        for prev_evt in reversed(events):
                            if (prev_evt.csid == csid_idx and
                                path_name in prev_evt.extra and
                                abs(prev_evt.ts_ms - hw_ts_ms) < 0.001):
                                if prev_evt.event_type != evt_type:
                                    sof_eof_collision = True
                                    if '!!SOF+EOF COLLISION!!' not in prev_evt.extra:
                                        prev_evt.extra += ' !!SOF+EOF COLLISION!!'
                                break

                extra = f'CSID:{csid_idx} {path_name}'
                if sof_eof_collision:
                    extra += ' !!SOF+EOF COLLISION!!'

                evt = Event(
                    timestamp=timestamp, ts_ms=hw_ts_ms,
                    event_type=evt_type, ctx=ctx_id,
                    link=link, csid=csid_idx,
                    frame_id=current_frame.get((ctx_id, link), -1),
                    req_id=current_req.get((ctx_id, link), -1),
                    extra=extra,
                    line_no=line_no
                )
                if _filter_event(evt, ctx_filter, link_filter):
                    events.append(evt)
                continue

            # 1. CSID path top half status (SOF/EOF detection) - legacy fallback
            #    Skipped for CSIDs that have parse_path_irq_status (HW timestamp preferred)
            m = csid_status_re.search(line)
            if m:
                csid_idx = int(m.group(1))
                if csid_idx in csid_has_hw_ts:
                    continue
                path_raw = m.group(2)  # "IPP", "IPP1", "RDI0", "COMP_IRQ", etc.
                status = int(m.group(3), 16)

                # Normalize path name from log format to resource name:
                #   "IPP"  -> IPP_0 (no digit suffix means index 0)
                #   "IPP1" -> IPP_1
                #   "RDI0" -> RDI_0
                #   "COMP_IRQ" -> skip (composite IRQ, not a path SOF/EOF)
                if path_raw == 'IPP':
                    path_name = 'IPP_0'
                elif path_raw.startswith('IPP') and path_raw[3:].isdigit():
                    path_name = f'IPP_{path_raw[3:]}'
                elif path_raw.startswith('RDI') and path_raw[3:].isdigit():
                    path_name = f'RDI_{path_raw[3:]}'
                else:
                    # COMP_IRQ or other non-path entries
                    continue

                # Only track IPP paths for SOF/EOF (primary pixel paths)
                if not path_name.startswith('IPP'):
                    continue

                # Apply CSID path filter (e.g., only show IPP_0)
                if csid_path_filter and path_name != csid_path_filter:
                    continue

                # Status is a bitmask: 0x1000 = SOF, 0x200 = EOF,
                # 0x200000 = EPOCH0, 0x400000 = EPOCH1, 0x800000 = RUP_ACK.
                # A single IRQ may carry multiple bits (e.g. 0x1200 = previous EOF
                # coalesced with next SOF). Emit EOF before SOF in that case so
                # the square wave goes high->low->high cleanly.
                evt_types = []
                if status & 0x200:
                    evt_types.append('EOF')
                if status & 0x1000:
                    evt_types.append('SOF')
                if status & 0x200000:
                    evt_types.append('EPOCH0')
                if status & 0x400000:
                    evt_types.append('EPOCH1')
                if not evt_types:
                    # 0x800000 RUP_ACK is handled by irq_handler; ignore everything else
                    continue

                # Map CSID+path to specific ctx using the learned mapping
                csid_key = f"{csid_idx}:{path_name}"
                ctx_id = csid_path_to_ctx.get(csid_key)
                if ctx_id is None:
                    continue

                link = ctx_link_map.get(ctx_id)
                if link is None:
                    continue

                for evt_type in evt_types:
                    evt = Event(
                        timestamp=timestamp, ts_ms=ts_ms,
                        event_type=evt_type, ctx=ctx_id,
                        link=link, csid=csid_idx,
                        frame_id=current_frame.get((ctx_id, link), -1),
                        req_id=current_req.get((ctx_id, link), -1),
                        extra=f'CSID:{csid_idx} {path_name}',
                        line_no=line_no
                    )
                    if _filter_event(evt, ctx_filter, link_filter):
                        events.append(evt)
                continue

            # 2. IRQ handler with evt_id (most informative for RUP/EPOCH)
            m = irq_handler_re.search(line)
            if m:
                evt_id = int(m.group(1))
                ctx_id = int(m.group(2))
                link = m.group(3).lower()

                evt_map = {2: 'RUP', 3: 'EPOCH0'}
                if evt_id not in evt_map:
                    continue

                evt_type = evt_map[evt_id]
                ctx_link_map[ctx_id] = link
                if link != '0xffffffff':
                    link_to_ctx[link] = ctx_id

                evt = Event(
                    timestamp=timestamp, ts_ms=ts_ms,
                    event_type=evt_type, ctx=ctx_id,
                    link=link,
                    frame_id=current_frame.get((ctx_id, link), -1),
                    req_id=current_req.get((ctx_id, link), -1),
                    line_no=line_no
                )
                if _filter_event(evt, ctx_filter, link_filter):
                    events.append(evt)
                if evt_type == 'RUP':
                    last_rup_event[(ctx_id, link)] = evt
                continue

            # 3. SOF timestamp update (frame_id and req_id tracking)
            m = sof_ts_re.search(line)
            if m:
                frame_id = int(m.group(1))
                ctx_id = int(m.group(2))
                req_id = int(m.group(3))
                link = m.group(4).lower()
                current_frame[(ctx_id, link)] = frame_id
                current_req[(ctx_id, link)] = req_id
                ctx_link_map[ctx_id] = link
                if link != '0xffffffff':
                    link_to_ctx[link] = ctx_id
                    req_link_to_ctx[(req_id, link)] = ctx_id
                # Retroactively fix the most recent RUP's frame/req: the RUP
                # log line prints before update_sof_ts in the same ISR, so it
                # captured stale values. Only fix if the RUP was within 5ms
                # (same bottom-half batch).
                prev_rup = last_rup_event.get((ctx_id, link))
                if prev_rup and abs(ts_ms - prev_rup.ts_ms) < 5.0:
                    prev_rup.frame_id = frame_id
                    prev_rup.req_id = req_id
                continue

            # 4. Handle CSID event (REG_UPDATE/EPOCH) - skip, use irq_handler
            m = csid_event_re.search(line)
            if m:
                continue

            # 5. cam_buf_done tracepoint (authoritative: has link_hdl and request).
            # Resolve ctx via (req, link) map (most reliable, learned from sof_ts);
            # fall back to link-only map. Skip if link is invalid or ctx unknown,
            # to avoid emitting bogus ctx=-1 / link=0xffffffff bindings.
            m = cam_buf_done_re.search(line)
            if m:
                req_id = int(m.group(1))
                link = m.group(2).lower()
                if link == '0xffffffff':
                    continue
                ctx_id = req_link_to_ctx.get((req_id, link))
                if ctx_id is None:
                    ctx_id = link_to_ctx.get(link)
                if ctx_id is None:
                    continue

                evt = Event(
                    timestamp=timestamp, ts_ms=ts_ms,
                    event_type='BUF_DONE', ctx=ctx_id,
                    link=link,
                    frame_id=current_frame.get((ctx_id, link), -1),
                    req_id=req_id,
                    extra=f'req={req_id}',
                    line_no=line_no
                )
                if _filter_event(evt, ctx_filter, link_filter):
                    events.append(evt)
                continue

            # 6. Handle IFE BUF_DONE event (fallback when tracepoint not available)
            m = ife_event_re.search(line)
            if m:
                ctx_id = int(m.group(3))
                link = ctx_link_map.get(ctx_id, '0x0')

                evt = Event(
                    timestamp=timestamp, ts_ms=ts_ms,
                    event_type='BUF_DONE', ctx=ctx_id,
                    link=link,
                    frame_id=current_frame.get((ctx_id, link), -1),
                    req_id=current_req.get((ctx_id, link), -1),
                    extra=f'IFE:{m.group(1)}',
                    line_no=line_no
                )
                if _filter_event(evt, ctx_filter, link_filter):
                    events.append(evt)
                continue

            # 7. BUF_DONE context entry (for ctx-link learning)
            m = buf_done_ctx_re.search(line)
            if m:
                ctx_id = int(m.group(1))
                link = m.group(2).lower()
                ctx_link_map[ctx_id] = link
                if link != '0xffffffff':
                    link_to_ctx[link] = ctx_id
                continue

    return events, dict(ctx_ipp_paths)


def _filter_event(evt: Event, ctx_filter: Optional[int],
                  link_filter: Optional[str]) -> bool:
    """Check if event passes filters."""
    if ctx_filter is not None and evt.ctx != ctx_filter:
        return False
    if link_filter is not None and evt.link != link_filter.lower():
        return False
    return True


def validate_and_associate_events(events: List[Event]) -> List[Event]:
    """Validate SOF/EOF pairing and associate SOF with subsequent RUP/EPOCH.

    Grouping is by CSID (which maps 1:1 to ctx and link).  RUP/EPOCH events
    from the IRQ handler don't carry a CSID field directly, so we build a
    ctx→csid reverse map from SOF/EOF events and assign CSID to RUP/EPOCH.

    Rules enforced:
    1. SOF must precede its paired EOF (by HW timestamp) on the same
       (csid, path). An EOF without a prior SOF is flagged as orphaned.
    2. Each SOF belongs to the next RUP on the same CSID that arrives after
       it (by timestamp). If no RUP follows, the next EPOCH is used instead.
    3. SOF+EOF arriving at the same HW timestamp is a collision error (already
       marked during parsing).
    """
    events.sort(key=lambda e: (e.ts_ms, e.line_no))

    # Build ctx→csid mapping from SOF/EOF events that have csid set
    ctx_to_csid: Dict[int, int] = {}
    for evt in events:
        if evt.csid >= 0:
            ctx_to_csid[evt.ctx] = evt.csid

    # Assign CSID to RUP/EPOCH events that lack it (from IRQ handler path)
    for evt in events:
        if evt.csid < 0 and evt.ctx in ctx_to_csid:
            evt.csid = ctx_to_csid[evt.ctx]

    # Group by CSID for pairing and association
    by_csid: Dict[int, List[Event]] = defaultdict(list)
    for evt in events:
        if evt.csid >= 0:
            by_csid[evt.csid].append(evt)

    for csid_idx, csid_events in by_csid.items():
        # --- SOF/EOF pairing per (csid, path) ---
        pending_sof: Dict[str, Event] = {}  # path_name -> SOF event

        for evt in csid_events:
            # Skip collision events from pairing logic — they are already
            # a known error and don't follow normal SOF→EOF sequencing.
            if '!!SOF+EOF COLLISION!!' in evt.extra:
                # Clear any pending SOF for this path since the collision
                # effectively resets the state machine.
                path = None
                for token in evt.extra.split():
                    if token.startswith('IPP_') or token.startswith('RDI_'):
                        path = token
                        break
                if path and path in pending_sof:
                    pending_sof.pop(path)
                continue

            path = None
            if evt.event_type in ('SOF', 'EOF'):
                for token in evt.extra.split():
                    if token.startswith('IPP_') or token.startswith('RDI_'):
                        path = token
                        break
                if path is None:
                    path = '_default'

            if evt.event_type == 'SOF':
                if path in pending_sof:
                    old_sof = pending_sof[path]
                    if '!!MISSING_EOF!!' not in old_sof.extra:
                        old_sof.extra += ' !!MISSING_EOF!!'
                pending_sof[path] = evt

            elif evt.event_type == 'EOF':
                if path in pending_sof:
                    sof_evt = pending_sof.pop(path)
                    sof_evt.paired_eof = evt
                    evt.paired_sof = sof_evt
                else:
                    if '!!ORPHAN_EOF!!' not in evt.extra:
                        evt.extra += ' !!ORPHAN_EOF!!'

        # --- SOF → RUP/EPOCH association per CSID ---
        # SOF belongs to the next RUP (or EPOCH if no RUP) on the same CSID.
        pending_sofs_for_rup: List[Event] = []

        for evt in csid_events:
            if evt.event_type == 'SOF':
                pending_sofs_for_rup.append(evt)
            elif evt.event_type == 'RUP':
                for sof in pending_sofs_for_rup:
                    sof.assoc_rup = evt
                pending_sofs_for_rup = []
            elif evt.event_type in ('EPOCH0', 'EPOCH1') and pending_sofs_for_rup:
                for sof in pending_sofs_for_rup:
                    if sof.assoc_rup is None:
                        sof.assoc_rup = evt
                pending_sofs_for_rup = []

    return events


def deduplicate_events(events: List[Event]) -> List[Event]:
    """Remove duplicate events that occur at the same timestamp for same ctx/link/type/extra."""
    seen = set()
    result = []
    for evt in events:
        key = (evt.timestamp, evt.event_type, evt.ctx, evt.link, evt.extra)
        if key not in seen:
            seen.add(key)
            result.append(evt)
    return result


def generate_timing_diagram(events: List[Event], use_color: bool = True,
                            max_width: int = 120) -> str:
    """Generate a text-based timing diagram."""
    if not events:
        return "No events found."

    events = deduplicate_events(events)
    events.sort(key=lambda e: (e.ts_ms, e.line_no))

    # Group by pipeline (ctx, link)
    pipelines: Dict[Tuple[int, str], List[Event]] = defaultdict(list)
    for evt in events:
        pipelines[(evt.ctx, evt.link)].append(evt)

    # Find time range
    t_start = events[0].ts_ms
    t_end = events[-1].ts_ms
    duration = t_end - t_start
    if duration == 0:
        duration = 1.0

    output_lines = []

    # Header
    output_lines.append("=" * max_width)
    output_lines.append("ISP TIMING DIAGRAM")
    output_lines.append("=" * max_width)
    output_lines.append("")

    # Legend
    output_lines.append("Legend:")
    for evt_type, symbol in EVENT_SYMBOLS.items():
        if use_color:
            output_lines.append(
                f"  {EVENT_COLORS[evt_type]}{symbol}{RESET_COLOR} = {evt_type}")
        else:
            output_lines.append(f"  {symbol} = {evt_type}")
    output_lines.append("")
    output_lines.append(f"Time range: {events[0].timestamp} -> {events[-1].timestamp} "
                        f"(duration: {duration:.1f}ms)")
    output_lines.append("")

    # Per-pipeline timing diagram
    for (ctx, link), pipe_events in sorted(pipelines.items()):
        output_lines.append("-" * max_width)
        output_lines.append(f"Pipeline: ctx={ctx}, link={link}")
        output_lines.append("-" * max_width)

        # Detailed event list
        output_lines.append("")
        output_lines.append("  Detailed Events:")
        output_lines.append(f"  {'Time':<20} {'Event':<10} {'Frame':<8} {'Info'}")
        output_lines.append(f"  {'----':<20} {'-----':<10} {'-----':<8} {'----'}")

        # Track frames for boundary display
        current_frame_id = -1
        for evt in pipe_events:
            frame_str = str(evt.frame_id) if evt.frame_id >= 0 else '-'
            sym = EVENT_SYMBOLS[evt.event_type]
            if use_color:
                sym = f"{EVENT_COLORS[evt.event_type]}{sym}{RESET_COLOR}"
                evt_str = f"{EVENT_COLORS[evt.event_type]}{evt.event_type:<10}{RESET_COLOR}"
            else:
                evt_str = f"{evt.event_type:<10}"

            # Frame boundary marker - only mark IPP_0 SOF as frame start
            frame_marker = ""
            is_master_sof = (evt.event_type == 'SOF' and 'IPP_0' in evt.extra)
            if is_master_sof and evt.frame_id != current_frame_id:
                if evt.frame_id >= 0:
                    frame_marker = f"<-- Frame {evt.frame_id} Start"
                    current_frame_id = evt.frame_id

            info = evt.extra if evt.extra else ""
            error_marker = ""
            if '!!SOF+EOF COLLISION!!' in info:
                if use_color:
                    error_marker = f" \033[1;91m*** ERROR: SOF+EOF SIMULTANEOUS ***\033[0m"
                else:
                    error_marker = " *** ERROR: SOF+EOF SIMULTANEOUS ***"
            elif '!!ORPHAN_EOF!!' in info:
                if use_color:
                    error_marker = f" \033[1;93m** EOF without prior SOF **\033[0m"
                else:
                    error_marker = " ** EOF without prior SOF **"
            elif '!!MISSING_EOF!!' in info:
                if use_color:
                    error_marker = f" \033[1;93m** SOF without subsequent EOF **\033[0m"
                else:
                    error_marker = " ** SOF without subsequent EOF **"

            # Show SOF→RUP/EPOCH association
            assoc_marker = ""
            if evt.event_type == 'SOF' and evt.assoc_rup is not None:
                assoc_type = evt.assoc_rup.event_type
                delta = evt.assoc_rup.ts_ms - evt.ts_ms
                assoc_marker = f" →{assoc_type}(+{delta:.2f}ms)"

            output_lines.append(
                f"  {evt.timestamp:<20} {sym} {evt_str} F{frame_str:<6} {info}{assoc_marker} {frame_marker}{error_marker}")

        # Timeline visualization
        output_lines.append("")
        output_lines.append("  Timeline:")

        # Calculate timeline width
        timeline_width = max_width - 20
        pipe_t_start = pipe_events[0].ts_ms
        pipe_t_end = pipe_events[-1].ts_ms
        pipe_duration = pipe_t_end - pipe_t_start
        if pipe_duration == 0:
            pipe_duration = 1.0

        # Build timeline string
        timeline = [' '] * timeline_width
        event_positions: List[Tuple[int, str, str]] = []  # (pos, symbol, type)

        for evt in pipe_events:
            pos = int((evt.ts_ms - pipe_t_start) / pipe_duration * (timeline_width - 1))
            pos = max(0, min(pos, timeline_width - 1))
            sym = EVENT_SYMBOLS[evt.event_type]
            event_positions.append((pos, sym, evt.event_type))

        # Place events on timeline (later events override earlier at same position)
        for pos, sym, evt_type in event_positions:
            timeline[pos] = sym

        # Print timeline with color
        timeline_str = ""
        for i, ch in enumerate(timeline):
            colored = False
            if ch != ' ':
                for pos, sym, evt_type in event_positions:
                    if pos == i:
                        if use_color:
                            timeline_str += f"{EVENT_COLORS[evt_type]}{ch}{RESET_COLOR}"
                        else:
                            timeline_str += ch
                        colored = True
                        break
            if not colored:
                timeline_str += ch

        # Time axis
        t_start_str = f"{pipe_events[0].timestamp.split()[-1]}"
        t_end_str = f"{pipe_events[-1].timestamp.split()[-1]}"

        output_lines.append(f"  |{timeline_str}|")
        output_lines.append(
            f"  {t_start_str}{' ' * (timeline_width - len(t_start_str) - len(t_end_str) + 2)}{t_end_str}")

        # Frame-level summary diagram
        output_lines.append("")
        output_lines.append("  Frame-level view:")

        # Group events by frame (use IPP_0 SOF as frame boundary)
        frame_events: Dict[int, List[Event]] = defaultdict(list)
        active_frame = -1
        for evt in pipe_events:
            is_master_sof = (evt.event_type == 'SOF' and 'IPP_0' in evt.extra)
            if is_master_sof and evt.frame_id >= 0:
                active_frame = evt.frame_id
            if active_frame >= 0:
                frame_events[active_frame].append(evt)

        for frame_id in sorted(frame_events.keys()):
            f_events = frame_events[frame_id]
            # Build a compact per-frame timeline
            event_sequence = []
            for e in f_events:
                sym = EVENT_SYMBOLS[e.event_type]
                if use_color:
                    sym = f"{EVENT_COLORS[e.event_type]}{sym}{RESET_COLOR}"
                event_sequence.append(sym)

            seq_str = " ".join(event_sequence)
            ts_range = f"{f_events[0].timestamp.split()[-1]}-{f_events[-1].timestamp.split()[-1]}"
            output_lines.append(f"    Frame {frame_id:>3}: [{seq_str}] ({ts_range})")

        output_lines.append("")

    # Summary statistics
    output_lines.append("=" * max_width)
    output_lines.append("SUMMARY")
    output_lines.append("=" * max_width)
    output_lines.append(f"  Total events parsed: {len(events)}")
    output_lines.append(f"  Pipelines detected: {len(pipelines)}")

    # Check for SOF+EOF collisions
    collision_events = [e for e in events if '!!SOF+EOF COLLISION!!' in e.extra]
    if collision_events:
        if use_color:
            output_lines.append(f"\n  \033[1;91m!!! SOF+EOF COLLISIONS DETECTED: {len(collision_events)} events !!!\033[0m")
        else:
            output_lines.append(f"\n  !!! SOF+EOF COLLISIONS DETECTED: {len(collision_events)} events !!!")
        output_lines.append(f"  This indicates SOF and EOF arrived at the same HW timestamp —")
        output_lines.append(f"  the sensor or CSID is likely out of sync.")
        for e in collision_events:
            output_lines.append(f"    @ {e.timestamp} ctx={e.ctx} {e.extra}")
        output_lines.append("")

    for (ctx, link), pipe_events in sorted(pipelines.items()):
        evt_counts = defaultdict(int)
        for e in pipe_events:
            evt_counts[e.event_type] += 1
        counts_str = ", ".join(f"{k}:{v}" for k, v in sorted(evt_counts.items()))
        output_lines.append(f"    ctx={ctx} link={link}: {counts_str}")

    # Inter-event timing analysis
    output_lines.append("")
    output_lines.append("  Inter-event timing (per pipeline):")
    for (ctx, link), pipe_events in sorted(pipelines.items()):
        output_lines.append(f"    ctx={ctx} link={link}:")
        # SOF-to-SOF intervals (frame period) - only use IPP_0 (master) SOFs
        sof_times = [e.ts_ms for e in pipe_events
                     if e.event_type == 'SOF' and 'IPP_0' in e.extra]
        if not sof_times:
            sof_times = [e.ts_ms for e in pipe_events if e.event_type == 'SOF']
        if len(sof_times) > 1:
            intervals = [sof_times[i+1] - sof_times[i] for i in range(len(sof_times)-1)]
            avg = sum(intervals) / len(intervals)
            output_lines.append(f"      SOF-to-SOF (frame period): avg={avg:.2f}ms "
                                f"min={min(intervals):.2f}ms max={max(intervals):.2f}ms "
                                f"(~{1000.0/avg:.1f} fps)")

        # SOF-to-RUP
        sof_rup_pairs = []
        last_sof_ts = None
        for e in pipe_events:
            if e.event_type == 'SOF':
                last_sof_ts = e.ts_ms
            elif e.event_type == 'RUP' and last_sof_ts is not None:
                sof_rup_pairs.append(e.ts_ms - last_sof_ts)
                last_sof_ts = None
        if sof_rup_pairs:
            avg = sum(sof_rup_pairs) / len(sof_rup_pairs)
            output_lines.append(f"      SOF-to-RUP: avg={avg:.2f}ms")

        # SOF-to-EPOCH
        sof_epoch_pairs = []
        last_sof_ts = None
        for e in pipe_events:
            if e.event_type == 'SOF':
                last_sof_ts = e.ts_ms
            elif e.event_type in ('EPOCH0', 'EPOCH1') and last_sof_ts is not None:
                sof_epoch_pairs.append(e.ts_ms - last_sof_ts)
                last_sof_ts = None
        if sof_epoch_pairs:
            avg = sum(sof_epoch_pairs) / len(sof_epoch_pairs)
            output_lines.append(f"      SOF-to-EPOCH: avg={avg:.2f}ms")

        # SOF-to-EOF
        sof_eof_pairs = []
        last_sof_ts = None
        for e in pipe_events:
            if e.event_type == 'SOF':
                last_sof_ts = e.ts_ms
            elif e.event_type == 'EOF' and last_sof_ts is not None:
                sof_eof_pairs.append(e.ts_ms - last_sof_ts)
                last_sof_ts = None
        if sof_eof_pairs:
            avg = sum(sof_eof_pairs) / len(sof_eof_pairs)
            output_lines.append(f"      SOF-to-EOF: avg={avg:.2f}ms")

        # RUP-to-BUF_DONE
        rup_bd_pairs = []
        last_rup_ts = None
        for e in pipe_events:
            if e.event_type == 'RUP':
                last_rup_ts = e.ts_ms
            elif e.event_type == 'BUF_DONE' and last_rup_ts is not None:
                rup_bd_pairs.append(e.ts_ms - last_rup_ts)
                last_rup_ts = None
        if rup_bd_pairs:
            avg = sum(rup_bd_pairs) / len(rup_bd_pairs)
            output_lines.append(f"      RUP-to-BUF_DONE: avg={avg:.2f}ms")

    output_lines.append("")
    return "\n".join(output_lines)


def generate_ascii_waveform(events: List[Event], use_color: bool = True,
                            max_width: int = 150) -> str:
    """Generate a waveform-style timing diagram (horizontal lanes per event type)."""
    if not events:
        return "No events found."

    events = deduplicate_events(events)
    events.sort(key=lambda e: (e.ts_ms, e.line_no))

    pipelines: Dict[Tuple[int, str], List[Event]] = defaultdict(list)
    for evt in events:
        pipelines[(evt.ctx, evt.link)].append(evt)

    output_lines = []
    output_lines.append("=" * max_width)
    output_lines.append("ISP WAVEFORM TIMING DIAGRAM")
    output_lines.append("=" * max_width)
    output_lines.append("")
    output_lines.append("Legend:  ▼=SOF  ▲=EOF  ■=RUP  ●=EPOCH0  ○=EPOCH1  ★=BUF_DONE")
    output_lines.append(f"        |...| = one frame boundary (SOF to next SOF)")
    output_lines.append("")

    for (ctx, link), pipe_events in sorted(pipelines.items()):
        output_lines.append(f"{'─' * max_width}")
        output_lines.append(f"Pipeline: ctx={ctx}, link={link}")
        output_lines.append(f"{'─' * max_width}")

        t_start = pipe_events[0].ts_ms
        t_end = pipe_events[-1].ts_ms
        t_range = t_end - t_start
        if t_range == 0:
            t_range = 1.0

        # Timeline width for waveform
        tw = max_width - 15  # label space

        # Create per-type lanes
        lane_types = ['SOF', 'RUP', 'EPOCH0', 'EPOCH1', 'BUF_DONE', 'EOF']
        lanes: Dict[str, List[str]] = {}
        for lt in lane_types:
            lanes[lt] = ['─'] * tw

        # Place events
        for evt in pipe_events:
            if evt.event_type not in lanes:
                continue
            pos = int((evt.ts_ms - t_start) / t_range * (tw - 1))
            pos = max(0, min(pos, tw - 1))
            sym = EVENT_SYMBOLS[evt.event_type]
            lanes[evt.event_type][pos] = sym

        # Print lanes
        for lt in lane_types:
            lane_str = "".join(lanes[lt])
            if use_color:
                colored_lane = ""
                for ch in lane_str:
                    if ch == EVENT_SYMBOLS[lt]:
                        colored_lane += f"{EVENT_COLORS[lt]}{ch}{RESET_COLOR}"
                    else:
                        colored_lane += ch
                output_lines.append(f"  {lt:<9}|{colored_lane}|")
            else:
                output_lines.append(f"  {lt:<9}|{lane_str}|")

        # Time axis
        t_start_str = pipe_events[0].timestamp.split()[-1]
        t_end_str = pipe_events[-1].timestamp.split()[-1]
        output_lines.append(
            f"  {'TIME':<9}|{t_start_str}"
            f"{' ' * (tw - len(t_start_str) - len(t_end_str))}{t_end_str}|")

        # Frame markers
        sof_positions = []
        for evt in pipe_events:
            if evt.event_type == 'SOF':
                pos = int((evt.ts_ms - t_start) / t_range * (tw - 1))
                pos = max(0, min(pos, tw - 1))
                sof_positions.append((pos, evt.frame_id))

        frame_line = [' '] * tw
        for pos, fid in sof_positions:
            label = f"F{fid}" if fid >= 0 else "F?"
            for i, ch in enumerate(label):
                if pos + i < tw:
                    frame_line[pos + i] = ch

        output_lines.append(f"  {'FRAME':<9}|{''.join(frame_line)}|")
        output_lines.append("")

    return "\n".join(output_lines)


def _evt_tooltip(evt: Event) -> str:
    """Build tooltip string for an event."""
    parts = [f"type={evt.event_type}",
             f"time={evt.timestamp}",
             f"ctx={evt.ctx}",
             f"link={evt.link}",
             f"frame={evt.frame_id}",
             f"req={evt.req_id}"]
    if evt.extra:
        parts.append(evt.extra)
    return " | ".join(parts)


def generate_html_timing(events: List[Event], max_width: int = 150,
                         ctx_ipp_paths: Optional[Dict[int, set]] = None,
                         filename: str = '') -> str:
    """Generate an interactive HTML timing diagram with zoom/pan and crosshair cursor."""
    if not events:
        return "<p>No events found.</p>"
    if ctx_ipp_paths is None:
        ctx_ipp_paths = {}

    events = deduplicate_events(events)
    events.sort(key=lambda e: (e.ts_ms, e.line_no))

    pipelines: Dict[Tuple[int, str], List[Event]] = defaultdict(list)
    for evt in events:
        pipelines[(evt.ctx, evt.link)].append(evt)

    import json

    # Serialize events to JSON for JavaScript rendering
    pipeline_data = {}
    for (ctx, link), pipe_events in sorted(pipelines.items()):
        is_2exp = len(ctx_ipp_paths.get(ctx, set())) > 1
        ipp_paths = sorted(ctx_ipp_paths.get(ctx, {'IPP_0'}))
        evt_list = []
        for e in pipe_events:
            evt_dict = {
                'ts': e.ts_ms,
                'timestamp': e.timestamp,
                'type': e.event_type,
                'ctx': e.ctx,
                'link': e.link,
                'frame': e.frame_id,
                'req': e.req_id,
                'extra': e.extra,
            }
            if e.event_type == 'SOF' and e.assoc_rup is not None:
                evt_dict['assoc_type'] = e.assoc_rup.event_type
                evt_dict['assoc_delta_ms'] = round(e.assoc_rup.ts_ms - e.ts_ms, 3)
            evt_list.append(evt_dict)
        key = f"ctx={ctx},link={link}"
        pipeline_data[key] = {
            'ctx': ctx,
            'link': link,
            'events': evt_list,
            'is_2exp': is_2exp,
            'ipp_paths': ipp_paths,
        }

    # Compute stats per pipeline for display
    stats_data = {}
    for (ctx, link), pipe_events in sorted(pipelines.items()):
        is_2exp = len(ctx_ipp_paths.get(ctx, set())) > 1
        sof_times = [e.ts_ms for e in pipe_events
                     if e.event_type == 'SOF' and 'IPP_0' in e.extra]
        if not sof_times:
            sof_times = [e.ts_ms for e in pipe_events if e.event_type == 'SOF']
        fps = 0
        avg_period = 0
        if len(sof_times) > 1:
            intervals = [sof_times[i+1] - sof_times[i] for i in range(len(sof_times)-1)]
            avg_period = sum(intervals) / len(intervals)
            fps = 1000.0 / avg_period if avg_period > 0 else 0
        key = f"ctx={ctx},link={link}"
        stats_data[key] = {
            'is_2exp': is_2exp,
            'ipp_paths': sorted(ctx_ipp_paths.get(ctx, {'IPP_0'})),
            'fps': round(fps, 1),
            'avg_period_ms': round(avg_period, 2),
            'num_events': len(pipe_events),
        }

    html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>ISP Timing Diagram</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #1a1a2e; color: #d4d4d4; font-family: "Consolas","Monaco",monospace; font-size: 13px; padding: 15px; }}
h2 {{ color: #e0e0e0; margin: 10px 0; display: flex; justify-content: space-between; align-items: center; }}
.filename {{ color: #888; font-size: 12px; font-weight: normal; }}
h3 {{ color: #ccc; margin: 8px 0 4px 0; font-size: 14px; }}
.pipeline {{ margin: 15px 0; padding: 12px; border: 1px solid #333; border-radius: 4px; background: #16213e; }}
.legend {{ display: flex; gap: 20px; margin: 8px 0; flex-wrap: wrap; font-size: 12px; }}
.legend-item {{ display: flex; align-items: center; gap: 5px; }}
.stats {{ font-size: 12px; color: #8899aa; margin: 6px 0; }}
.svg-container {{ position: relative; overflow: hidden; border: 1px solid #333; border-radius: 3px; background: #0f0f23; cursor: crosshair; }}
svg {{ display: block; }}
.controls {{ margin: 5px 0; font-size: 11px; color: #667; }}
.controls button {{ background: #2a2a4a; color: #aaa; border: 1px solid #444; border-radius: 3px; padding: 2px 8px; cursor: pointer; margin: 0 3px; font-size: 11px; }}
.controls button:hover {{ background: #3a3a5a; color: #fff; }}
#info-panel {{ position: fixed; top: 10px; right: 10px; background: #1e1e3e; border: 1px solid #4ec9b0; border-radius: 4px; padding: 8px 12px; font-size: 12px; min-width: 250px; z-index: 1000; display: none; pointer-events: none; }}
#info-panel .label {{ color: #888; }}
#info-panel .value {{ color: #4ec9b0; }}
details {{ margin: 8px 0; }}
summary {{ cursor: pointer; color: #569cd6; font-size: 12px; }}
.table-wrap {{ max-height: 350px; overflow-y: auto; margin-top: 5px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 11px; }}
th, td {{ padding: 2px 8px; text-align: left; border-bottom: 1px solid #222; }}
th {{ color: #667; background: #16213e; position: sticky; top: 0; }}
.measure-panel {{ background: #12122a; border: 1px solid #333; border-radius: 4px; padding: 6px 8px; font-size: 11px; margin-top: 6px; max-height: 200px; overflow-y: auto; display: none; }}
.measure-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px; border-bottom: 1px solid #333; padding-bottom: 4px; }}
.measure-header span {{ color: #aaa; font-weight: bold; font-size: 12px; }}
.measure-header button {{ background: #2a2a4a; color: #aaa; border: 1px solid #444; border-radius: 3px; padding: 1px 6px; cursor: pointer; font-size: 10px; }}
.measure-header button:hover {{ background: #3a3a5a; color: #fff; }}
.mp-clear {{ background: #4a2020 !important; color: #e06c75 !important; border: 1px solid #633 !important; }}
.mp-clear:hover {{ background: #633 !important; }}
.measure-item .m-mode {{ color: #555; font-size: 9px; margin-left: 3px; }}
.measure-hint {{ color: #555; font-style: italic; font-size: 10px; margin-top: 4px; }}
.measure-item {{ display: flex; align-items: center; gap: 5px; padding: 3px 0; border-bottom: 1px solid #222; }}
.measure-item input[type=checkbox] {{ margin: 0; cursor: pointer; }}
.measure-item .m-color {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
.measure-item .m-delta {{ font-weight: bold; min-width: 70px; }}
.measure-item .m-desc {{ color: #888; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.measure-item .m-remove {{ color: #666; cursor: pointer; padding: 0 4px; font-size: 14px; line-height: 1; }}
.measure-item .m-remove:hover {{ color: #e06c75; }}
.lane-toggles {{ display: flex; align-items: center; gap: 4px; margin: 6px 0; flex-wrap: wrap; font-size: 11px; }}
.lane-toggles .toggle-label {{ color: #667; margin-right: 2px; }}
.lane-toggles .toggle-sep {{ color: #444; margin: 0 6px; }}
.toggle-cb {{ display: inline-flex; align-items: center; gap: 3px; cursor: pointer; padding: 1px 5px; border-radius: 3px; background: #1a1a3a; border: 1px solid #333; }}
.toggle-cb:hover {{ border-color: #555; }}
.toggle-cb input {{ margin: 0; cursor: pointer; }}
.toggle-cb span {{ font-size: 11px; }}
</style>
</head><body>
<h2><span>ISP Timing Diagram</span><span class="filename">{filename}</span></h2>
<div class="legend">
  <div class="legend-item"><svg width="30" height="14"><path d="M0,12 L0,2 L30,2" stroke="#4ec9b0" fill="none" stroke-width="2"/></svg><span>SOF↑/EOF↓ (IPP_0)</span></div>
  <div class="legend-item"><svg width="30" height="14"><path d="M0,12 L0,2 L30,2" stroke="#9cdcfe" fill="none" stroke-width="2"/></svg><span>SOF↑/EOF↓ (IPP_1, 2EXP)</span></div>
  <div class="legend-item"><svg width="30" height="14"><path d="M0,12 L0,2 L30,2" stroke="#b8a0d4" fill="none" stroke-width="2"/></svg><span>SOF↑/EOF↓ (IPP_2, 3EXP)</span></div>
  <div class="legend-item"><span style="color:#569cd6;font-size:16px">▮</span><span>RUP</span></div>
  <div class="legend-item"><span style="color:#dcdcaa;font-size:16px">◆</span><span>EPOCH0</span></div>
  <div class="legend-item"><span style="color:#d4be98;font-size:16px">◇</span><span>EPOCH1</span></div>
  <div class="legend-item"><span style="color:#c586c0;font-size:16px">★</span><span>BUF_DONE</span></div>
  <div class="legend-item"><svg width="14" height="14"><polygon points="7,2 3,8 11,8" fill="none" stroke="#ff4500" stroke-width="1.2" stroke-dasharray="2,1.5"/></svg><span>SOF w/o prior EOF</span></div>
  <div class="legend-item"><svg width="14" height="14"><polygon points="7,12 3,6 11,6" fill="none" stroke="#ff4500" stroke-width="1.2" stroke-dasharray="2,1.5"/></svg><span>EOF w/o prior SOF</span></div>
  <div class="legend-item"><svg width="16" height="16"><rect x="1" y="1" width="14" height="14" fill="#ff000033" stroke="#ff0000" stroke-width="2"/><text x="8" y="12" text-anchor="middle" fill="#ff0000" font-size="10" font-weight="bold">!</text></svg><span style="color:#ff0000;font-weight:bold">SOF+EOF Collision (ERROR)</span></div>
</div>
<div class="controls">
  Scroll to zoom | Drag to pan | Hover for crosshair + details
  <span style="margin-left:20px">
    <button id="btn-sync-zoom">🔗 Sync Zoom: OFF</button>
    <button id="btn-merge-view">⊞ Merge View</button>
    <button id="btn-measure">📏 Measure: OFF</button>
  </span>
</div>
<div id="merged-container" style="display:none"></div>
<div id="info-panel">
  <div><span class="label">Time: </span><span class="value" id="info-time">-</span></div>
  <div><span class="label">Event: </span><span class="value" id="info-event">-</span></div>
  <div><span class="label">Frame: </span><span class="value" id="info-frame">-</span></div>
  <div><span class="label">Req: </span><span class="value" id="info-req">-</span></div>
  <div><span class="label">Ctx/Link: </span><span class="value" id="info-ctx">-</span></div>
  <div><span class="label">Path: </span><span class="value" id="info-path">-</span></div>
  <div id="info-assoc-row" style="display:none"><span class="label">Assoc: </span><span class="value" id="info-assoc">-</span></div>
  <div id="info-warn-row" style="display:none;color:#ff4500;font-weight:bold;margin-top:4px"><span id="info-warn">-</span></div>
</div>

<script>
const PIPELINES = {json.dumps(pipeline_data)};
const STATS = {json.dumps(stats_data)};

const COLORS = {{
  SOF: '#4ec9b0', EOF: '#4ec9b0', FRAME: '#4ec9b0', FRAME2: '#9cdcfe',
  RUP: '#569cd6', EPOCH0: '#dcdcaa', EPOCH1: '#d4be98', BUF_DONE: '#c586c0',
}};

const LANE_H = 50, LANE_GAP = 8, MARGIN_L = 90, MARGIN_R = 20, MARGIN_T = 10;

class TimingView {{
  constructor(container, pipeKey, pipeData, {{skipInitRender = false}} = {{}}) {{
    this.container = container;
    this.key = pipeKey;
    this.data = pipeData;
    this.events = pipeData.events;

    const ts_list = this.events.map(e => e.ts);
    this.t_min = Math.min(...ts_list);
    this.t_max = Math.max(...ts_list);
    this.t_range = this.t_max - this.t_min || 1;

    // View window (in ms)
    this.view_start = this.t_min;
    this.view_end = this.t_max;

    this.lanes = ['FRAME', 'RUP', 'EPOCH0', 'EPOCH1', 'BUF_DONE'];
    this.visibleLanes = new Set(this.lanes);
    this.visiblePaths = new Set(pipeData.ipp_paths);
    this.svgWidth = container.clientWidth || 1200;
    this.svgHeight = this.lanes.length * (LANE_H + LANE_GAP) + 50;
    this.plotWidth = this.svgWidth - MARGIN_L - MARGIN_R;

    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.setAttribute('width', this.svgWidth);
    this.svg.setAttribute('height', this.svgHeight);
    container.appendChild(this.svg);

    // Crosshair elements
    this.crossV = this._line(0, 0, 0, this.svgHeight, '#4ec9b044', 1);
    this.crossH = this._line(0, 0, this.svgWidth, 0, '#4ec9b044', 1);
    this.crossV.style.display = 'none';
    this.crossH.style.display = 'none';
    this.timeLabel = this._text(0, 0, '', '#4ec9b0', 10);
    this.timeLabel.style.display = 'none';

    this.dragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;
    this.dragViewStart = 0;
    this.dragViewEnd = 0;

    // Measurement state
    this.measureStart = null; // {{ts, type, frame, extra}}
    this.measurements = [];   // [{{id, startEvt, endEvt, delta_ms, color}}]
    this.measureIdCounter = 0;
    this._startMarkerEl = null;

    this._bindEvents();
    if (!skipInitRender) this.render();
  }}

  _ns(tag) {{ return document.createElementNS('http://www.w3.org/2000/svg', tag); }}

  _line(x1, y1, x2, y2, stroke, width) {{
    const l = this._ns('line');
    l.setAttribute('x1', x1); l.setAttribute('y1', y1);
    l.setAttribute('x2', x2); l.setAttribute('y2', y2);
    l.setAttribute('stroke', stroke); l.setAttribute('stroke-width', width);
    this.svg.appendChild(l);
    return l;
  }}

  _text(x, y, text, fill, size) {{
    const t = this._ns('text');
    t.setAttribute('x', x); t.setAttribute('y', y);
    t.setAttribute('fill', fill); t.setAttribute('font-size', size || 11);
    t.textContent = text;
    this.svg.appendChild(t);
    return t;
  }}

  _bindEvents() {{
    const el = this.container;
    el.addEventListener('wheel', (e) => {{
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const frac = (mx - MARGIN_L) / this.plotWidth;
      const pivot = this.view_start + frac * (this.view_end - this.view_start);
      const factor = e.deltaY > 0 ? 1.3 : 0.7;
      let newStart = pivot - (pivot - this.view_start) * factor;
      let newEnd = pivot + (this.view_end - pivot) * factor;
      // Clamp
      if (newStart < this.t_min) newStart = this.t_min;
      if (newEnd > this.t_max) newEnd = this.t_max;
      if (newEnd - newStart < 0.1) return; // min zoom
      this.view_start = newStart;
      this.view_end = newEnd;
      this.render();
    }});

    el.addEventListener('mousedown', (e) => {{
      this.dragging = true;
      this.dragStartX = e.clientX;
      this.dragStartY = e.clientY;
      this.dragViewStart = this.view_start;
      this.dragViewEnd = this.view_end;
      el.style.cursor = 'grabbing';
    }});

    document.addEventListener('mousemove', (e) => {{
      if (this.dragging) {{
        const dx = e.clientX - this.dragStartX;
        const dt = -dx / this.plotWidth * (this.dragViewEnd - this.dragViewStart);
        let ns = this.dragViewStart + dt;
        let ne = this.dragViewEnd + dt;
        if (ns < this.t_min) {{ ne += this.t_min - ns; ns = this.t_min; }}
        if (ne > this.t_max) {{ ns -= ne - this.t_max; ne = this.t_max; }}
        this.view_start = ns;
        this.view_end = ne;
        this.render();
      }}
    }});

    document.addEventListener('mouseup', (e) => {{
      const wasDrag = Math.abs(e.clientX - this.dragStartX) > 3 || Math.abs(e.clientY - this.dragStartY) > 3;
      this.dragging = false;
      el.style.cursor = 'crosshair';
      // If it was a click (not a drag), handle measurement
      if (!wasDrag && el.contains(e.target)) {{
        const rect = el.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        this._handleMeasureClick(mx, my);
      }}
    }});

    el.addEventListener('mousemove', (e) => {{
      if (this.dragging) return;
      const rect = el.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      this._showCrosshair(mx, my);
    }});

    el.addEventListener('mouseleave', () => {{
      this.crossV.style.display = 'none';
      this.crossH.style.display = 'none';
      this.timeLabel.style.display = 'none';
      document.getElementById('info-panel').style.display = 'none';
    }});
  }}

  _getLaneAtY(my) {{
    // Determine which lane the cursor is hovering over
    for (let li = 0; li < this.lanes.length; li++) {{
      const ly = li * (LANE_H + LANE_GAP) + MARGIN_T;
      if (my >= ly && my < ly + LANE_H) return this.lanes[li];
    }}
    return null;
  }}

  _isEvtVisible(evt) {{
    const lane = (evt.type === 'SOF' || evt.type === 'EOF') ? 'FRAME' : evt.type;
    if (!this.visibleLanes.has(lane)) return false;
    if ((evt.type === 'SOF' || evt.type === 'EOF') && evt.extra) {{
      const pathMatch = evt.extra.match(/IPP_\d+/);
      if (pathMatch && !this.visiblePaths.has(pathMatch[0])) return false;
    }}
    return true;
  }}

  _getEvtY(evt) {{
    // Get the Y position where a given event's marker is drawn
    const laneIdx = this.lanes.indexOf(evt.type === 'SOF' || evt.type === 'EOF' ? 'FRAME' : evt.type);
    if (laneIdx < 0) return -1;
    const ly = laneIdx * (LANE_H + LANE_GAP) + MARGIN_T;
    const highY = ly + 8, lowY = ly + 40, midY = ly + 24;

    if (evt.type === 'SOF') return highY;
    if (evt.type === 'EOF') return lowY;
    return midY;
  }}

  _showCrosshair(mx, my) {{
    this.crossV.setAttribute('x1', mx); this.crossV.setAttribute('x2', mx);
    this.crossV.setAttribute('y1', 0); this.crossV.setAttribute('y2', this.svgHeight);
    this.crossH.setAttribute('x1', MARGIN_L); this.crossH.setAttribute('x2', MARGIN_L + this.plotWidth);
    this.crossH.setAttribute('y1', my); this.crossH.setAttribute('y2', my);
    this.crossV.style.display = ''; this.crossH.style.display = '';

    // Compute time at cursor
    const frac = (mx - MARGIN_L) / this.plotWidth;
    const t_ms = this.view_start + frac * (this.view_end - this.view_start);
    const rel_ms = t_ms - this.t_min;
    const tl = this.timeLabel;
    tl.setAttribute('x', mx + 5);
    tl.setAttribute('y', this.svgHeight - 5);
    tl.textContent = rel_ms.toFixed(3) + 'ms';
    tl.style.display = '';

    // Determine which lane the cursor is in
    const hoveredLane = this._getLaneAtY(my);

    // Find nearest event by 2D distance, restricted to hovered lane
    let nearest = null, minDist = Infinity;
    for (const evt of this.events) {{
      if (evt.ts < this.view_start || evt.ts > this.view_end) continue;
      if (!this._isEvtVisible(evt)) continue;
      // Map event type to lane
      const evtLane = (evt.type === 'SOF' || evt.type === 'EOF') ? 'FRAME' : evt.type;
      if (hoveredLane && evtLane !== hoveredLane) continue;

      const ex = this.tsToX(evt.ts);
      const ey = this._getEvtY(evt);
      const dx = ex - mx;
      const dy = ey - my;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < minDist) {{ minDist = dist; nearest = evt; }}
    }}

    const panel = document.getElementById('info-panel');
    if (nearest && minDist < 20) {{
      panel.style.display = 'block';
      document.getElementById('info-time').textContent = nearest.timestamp + ' (+' + (nearest.ts - this.t_min).toFixed(3) + 'ms)';
      document.getElementById('info-event').textContent = nearest.type;
      document.getElementById('info-frame').textContent = nearest.frame >= 0 ? nearest.frame : '-';
      document.getElementById('info-req').textContent = nearest.req >= 0 ? nearest.req : '-';
      document.getElementById('info-ctx').textContent = 'ctx=' + nearest.ctx + ' link=' + nearest.link;
      document.getElementById('info-path').textContent = nearest.extra || '-';
      const assocRow = document.getElementById('info-assoc-row');
      if (nearest.assoc_type) {{
        assocRow.style.display = 'block';
        document.getElementById('info-assoc').textContent = 'SOF → ' + nearest.assoc_type + ' (+' + nearest.assoc_delta_ms + 'ms)';
      }} else {{
        assocRow.style.display = 'none';
      }}
      const warnRow = document.getElementById('info-warn-row');
      let warnMsg = '';
      if (nearest._anomaly) warnMsg = nearest._anomaly;
      else if (nearest.extra && nearest.extra.includes('ORPHAN_EOF')) warnMsg = 'EOF arrived without a prior SOF — unpaired';
      else if (nearest.extra && nearest.extra.includes('MISSING_EOF')) warnMsg = 'SOF has no subsequent EOF — frame never ended';
      else if (nearest.extra && nearest.extra.includes('SOF+EOF COLLISION')) warnMsg = 'SOF and EOF arrived simultaneously — sensor/CSID out of sync!';
      if (warnMsg) {{
        warnRow.style.display = 'block';
        document.getElementById('info-warn').textContent = '⚠ ' + warnMsg;
      }} else {{
        warnRow.style.display = 'none';
      }}
    }} else {{
      panel.style.display = 'none';
    }}
  }}

  _handleMeasureClick(mx, my) {{
    if (!measureEnabled) return;

    // Find nearest event at click position
    const hoveredLane = this._getLaneAtY(my);
    let nearest = null, minDist = Infinity;
    for (const evt of this.events) {{
      if (evt.ts < this.view_start || evt.ts > this.view_end) continue;
      if (!this._isEvtVisible(evt)) continue;
      const evtLane = (evt.type === 'SOF' || evt.type === 'EOF') ? 'FRAME' : evt.type;
      if (hoveredLane && evtLane !== hoveredLane) continue;
      const ex = this.tsToX(evt.ts);
      const ey = this._getEvtY(evt);
      const dist = Math.sqrt((ex-mx)**2 + (ey-my)**2);
      if (dist < minDist) {{ minDist = dist; nearest = evt; }}
    }}

    if (!nearest || minDist > 25) {{
      // Click on empty area: raw time point
      const frac = (mx - MARGIN_L) / this.plotWidth;
      const t = this.view_start + frac * (this.view_end - this.view_start);
      nearest = {{ ts: t, type: 'cursor', timestamp: t.toFixed(3)+'ms', frame: -1, req: -1, extra: '', ctx: '', link: '' }};
    }}

    if (!this.measureStart) {{
      // First click: set start point and draw marker
      this.measureStart = nearest;
      this.container.style.outline = '2px solid #e5c07b88';
      this._drawStartMarker(nearest);
    }} else {{
      // Second click: compute delta and record
      const startEvt = this.measureStart;
      const endEvt = nearest;
      const delta = endEvt.ts - startEvt.ts;
      const colors = ['#4ec9b0','#e06c75','#61afef','#d19a66','#98c379','#c678dd','#56b6c2'];
      const color = colors[this.measureIdCounter % colors.length];
      const id = this.measureIdCounter++;
      const m = {{
        id, startEvt, endEvt,
        delta_ms: delta,
        color,
        visible: true,
      }};
      this.measurements.push(m);
      this.measureStart = null;
      this.container.style.outline = '';
      this._clearStartMarker();
      this.render();
      this._renderMeasurePanel();
    }}
  }}

  _drawStartMarker(evt) {{
    // Draw a prominent marker at the selected start point
    this._clearStartMarker();
    const x = this.tsToX(evt.ts);
    const g = this._ns('g');
    g.setAttribute('class', 'measure-start-marker');

    // Vertical dashed line across all lanes
    const vl = this._ns('line');
    vl.setAttribute('x1', x); vl.setAttribute('x2', x);
    vl.setAttribute('y1', MARGIN_T); vl.setAttribute('y2', this.svgHeight - 30);
    vl.setAttribute('stroke', '#e5c07b'); vl.setAttribute('stroke-width', 2);
    vl.setAttribute('stroke-dasharray', '4,3');
    g.appendChild(vl);

    // Circle at event position
    const ey = this._getEvtY(evt);
    if (ey > 0) {{
      const c = this._ns('circle');
      c.setAttribute('cx', x); c.setAttribute('cy', ey);
      c.setAttribute('r', 6); c.setAttribute('fill', 'none');
      c.setAttribute('stroke', '#e5c07b'); c.setAttribute('stroke-width', 2);
      g.appendChild(c);
    }}

    // Label "START" at top
    const t = this._ns('text');
    t.setAttribute('x', x); t.setAttribute('y', MARGIN_T - 2);
    t.setAttribute('fill', '#e5c07b'); t.setAttribute('font-size', 9);
    t.setAttribute('text-anchor', 'middle'); t.setAttribute('font-weight', 'bold');
    t.textContent = '▼ START';
    g.appendChild(t);

    this.svg.appendChild(g);
    this._startMarkerEl = g;
  }}

  _clearStartMarker() {{
    if (this._startMarkerEl && this._startMarkerEl.parentNode) {{
      this._startMarkerEl.parentNode.removeChild(this._startMarkerEl);
    }}
    this._startMarkerEl = null;
  }}

  removeMeasurement(id) {{
    this.measurements = this.measurements.filter(m => m.id !== id);
    this.render();
  }}

  toggleMeasurement(id, visible) {{
    const m = this.measurements.find(m => m.id === id);
    if (m) {{ m.visible = visible; this.render(); }}
  }}

  clearMeasurements() {{
    this.measurements = [];
    this.measureStart = null;
    this.container.style.outline = '';
    this.render();
    this._renderMeasurePanel();
  }}

  _initMeasurePanel() {{
    // Create per-view measure panel below the SVG container
    const panel = document.createElement('div');
    panel.className = 'measure-panel';
    const shortName = this.key === 'merged' ? 'Merged View' : this.key;
    panel.innerHTML = `
      <div class="measure-header">
        <span>📏 ${{shortName}}</span>
        <span>
          <button class="mp-minimize" title="Minimize">─</button>
          <button class="mp-clear" title="Clear all">Clear</button>
        </span>
      </div>
      <div class="mp-body">
        <div class="mp-list"></div>
        <div class="measure-hint">Click two points to measure</div>
      </div>
    `;
    // Insert after the svg-container in the parent pipeline div
    this.container.parentNode.insertBefore(panel, this.container.nextSibling);
    this._measurePanel = panel;
    this._measureList = panel.querySelector('.mp-list');
    this._measureHint = panel.querySelector('.measure-hint');
    this._measureBody = panel.querySelector('.mp-body');

    panel.querySelector('.mp-clear').addEventListener('click', () => {{
      this.clearMeasurements();
    }});
    panel.querySelector('.mp-minimize').addEventListener('click', function() {{
      const body = this.closest('.measure-panel').querySelector('.mp-body');
      if (body.style.display === 'none') {{
        body.style.display = 'block';
        this.textContent = '─';
      }} else {{
        body.style.display = 'none';
        this.textContent = '□';
      }}
    }});
  }}

  _renderMeasurePanel() {{
    if (!this._measurePanel) this._initMeasurePanel();
    const list = this._measureList;
    const hint = this._measureHint;
    list.innerHTML = '';
    if (this.measurements.length === 0) {{
      hint.style.display = 'block';
      return;
    }}
    hint.style.display = 'none';
    for (const item of this.measurements) {{
      const div = document.createElement('div');
      div.className = 'measure-item';
      const sign = item.delta_ms >= 0 ? '+' : '';
      const startLabel = item.startEvt.type + (item.startEvt.frame >= 0 ? '(F'+item.startEvt.frame+')' : '');
      const endLabel = item.endEvt.type + (item.endEvt.frame >= 0 ? '(F'+item.endEvt.frame+')' : '');
      div.innerHTML = `
        <input type="checkbox" ${{item.visible ? 'checked' : ''}} data-id="${{item.id}}">
        <span class="m-color" style="background:${{item.color}}"></span>
        <span class="m-delta" style="color:${{item.color}}">${{sign}}${{Math.abs(item.delta_ms).toFixed(3)}}ms</span>
        <span class="m-desc">${{startLabel}} → ${{endLabel}}</span>
        <span class="m-remove" data-id="${{item.id}}">×</span>
      `;
      list.appendChild(div);
    }}
    const self = this;
    list.querySelectorAll('input[type=checkbox]').forEach(cb => {{
      cb.addEventListener('change', (e) => {{
        self.toggleMeasurement(parseInt(e.target.dataset.id), e.target.checked);
      }});
    }});
    list.querySelectorAll('.m-remove').forEach(btn => {{
      btn.addEventListener('click', (e) => {{
        self.removeMeasurement(parseInt(e.target.dataset.id));
        self._renderMeasurePanel();
      }});
    }});
  }}

  _drawMeasurements() {{
    for (const m of this.measurements) {{
      if (!m.visible) continue;
      const x1 = this.tsToX(m.startEvt.ts);
      const x2 = this.tsToX(m.endEvt.ts);
      const lx = Math.min(x1, x2), rx = Math.max(x1, x2);
      // Skip if completely outside view
      if (rx < MARGIN_L || lx > MARGIN_L + this.plotWidth) continue;

      // Highlight region
      const rect = this._ns('rect');
      rect.setAttribute('x', Math.max(lx, MARGIN_L));
      rect.setAttribute('y', MARGIN_T);
      rect.setAttribute('width', Math.min(rx, MARGIN_L + this.plotWidth) - Math.max(lx, MARGIN_L));
      rect.setAttribute('height', this.svgHeight - MARGIN_T - 30);
      rect.setAttribute('fill', m.color);
      rect.setAttribute('opacity', 0.08);
      this.svg.appendChild(rect);

      // Vertical lines at start/end
      for (const x of [x1, x2]) {{
        if (x >= MARGIN_L && x <= MARGIN_L + this.plotWidth) {{
          const vl = this._ns('line');
          vl.setAttribute('x1', x); vl.setAttribute('x2', x);
          vl.setAttribute('y1', MARGIN_T); vl.setAttribute('y2', this.svgHeight - 30);
          vl.setAttribute('stroke', m.color); vl.setAttribute('stroke-width', 1);
          vl.setAttribute('stroke-dasharray', '3,2'); vl.setAttribute('opacity', 0.6);
          this.svg.appendChild(vl);
        }}
      }}

      // Delta label at top
      const midX = (Math.max(lx, MARGIN_L) + Math.min(rx, MARGIN_L + this.plotWidth)) / 2;
      if (midX >= MARGIN_L && midX <= MARGIN_L + this.plotWidth) {{
        const label = Math.abs(m.delta_ms).toFixed(3) + 'ms';
        const t = this._ns('text');
        t.setAttribute('x', midX); t.setAttribute('y', MARGIN_T - 2);
        t.setAttribute('fill', m.color); t.setAttribute('font-size', 10);
        t.setAttribute('text-anchor', 'middle'); t.setAttribute('font-weight', 'bold');
        t.textContent = (m.delta_ms >= 0 ? '+' : '') + label;
        this.svg.appendChild(t);
      }}
    }}
  }}

  tsToX(ts) {{
    return MARGIN_L + (ts - this.view_start) / (this.view_end - this.view_start) * this.plotWidth;
  }}

  render() {{
    // Clear SVG except crosshair elements
    while (this.svg.firstChild) this.svg.removeChild(this.svg.firstChild);
    // Re-add crosshair
    this.svg.appendChild(this.crossV);
    this.svg.appendChild(this.crossH);
    this.svg.appendChild(this.timeLabel);

    const vs = this.view_start, ve = this.view_end;

    // Draw lanes
    for (let li = 0; li < this.lanes.length; li++) {{
      const laneName = this.lanes[li];
      if (!this.visibleLanes.has(laneName)) continue;
      const ly = li * (LANE_H + LANE_GAP) + MARGIN_T;
      const highY = ly + 8, lowY = ly + 40, midY = ly + 24;

      // Lane label
      this._text(5, ly + 26, laneName, '#778', 11);

      // Baseline
      const bl = this._ns('line');
      bl.setAttribute('x1', MARGIN_L); bl.setAttribute('x2', MARGIN_L + this.plotWidth);
      bl.setAttribute('y1', lowY); bl.setAttribute('y2', lowY);
      bl.setAttribute('stroke', '#222'); bl.setAttribute('stroke-width', 0.5);
      this.svg.appendChild(bl);

      if (laneName === 'FRAME') {{
        this._drawFrameLane(ly, highY, lowY, vs, ve);
      }} else {{
        this._drawMarkerLane(laneName, midY, vs, ve);
      }}
    }}

    // Time axis
    this._drawTimeAxis();
    // Measurement overlays
    this._drawMeasurements();
    // Redraw start marker if pending
    if (this.measureStart) this._drawStartMarker(this.measureStart);
  }}

  _drawFrameLane(ly, highY, lowY, vs, ve) {{
    const isMultiExp = this.data.is_2exp;
    const paths = this.data.ipp_paths.filter(p => this.visiblePaths.has(p));

    if (paths.length === 0) return;

    if (isMultiExp && paths.length > 1) {{
      const numPaths = paths.length;
      const subH = (lowY - highY - 4 * (numPaths - 1)) / numPaths;
      const colors = {{'IPP_0': '#4ec9b0', 'IPP_1': '#9cdcfe', 'IPP_2': '#b8a0d4'}};
      paths.forEach((path, idx) => {{
        const sH = highY + idx * (subH + 4);
        const sL = sH + subH;
        const color = colors[path] || '#4ec9b0';
        this._text(MARGIN_L - 5, sH + subH/2 + 3, path, color, 9).setAttribute('text-anchor', 'end');
        this._drawSquareWave(path, sH, sL, color, vs, ve);
      }});
    }} else {{
      const singlePath = paths[0];
      const colors = {{'IPP_0': '#4ec9b0', 'IPP_1': '#9cdcfe', 'IPP_2': '#b8a0d4'}};
      this._drawSquareWave(singlePath, highY, lowY, colors[singlePath] || '#4ec9b0', vs, ve);
    }}
  }}

  _drawSquareWave(pathFilter, highY, lowY, color, vs, ve) {{
    const sof_eof = this.events.filter(e =>
      (e.type === 'SOF' || e.type === 'EOF') && e.extra.includes(pathFilter) &&
      e.ts >= vs && e.ts <= ve
    );

    if (sof_eof.length === 0) return;

    // Determine initial state: replay events before view_start with idempotent
    // transitions (don't toggle on duplicates from missed boundaries).
    const allBefore = this.events.filter(e =>
      (e.type === 'SOF' || e.type === 'EOF') && e.extra.includes(pathFilter) && e.ts < vs
    );
    let state = 'low';
    for (const e of allBefore) {{
      if (e.type === 'SOF' && state !== 'high') state = 'high';
      else if (e.type === 'EOF' && state !== 'low') state = 'low';
    }}

    let d = '';
    const startX = MARGIN_L;
    const startY = state === 'high' ? highY : lowY;
    d += `M${{startX}},${{startY}}`;

    // Idempotent transitions: a SOF when state is already 'high' (or EOF when
    // already 'low') means we missed the matching boundary in the log. Drawing
    // a down/up spike at the same X creates a folded waveform; instead skip the
    // transition so the wave stays clean. Flag those events as anomalies so the
    // dot markers below can highlight them with a distinct ring.
    // Clear stale flags first — anomaly status can change with zoom/initial state.
    for (const evt of sof_eof) delete evt._anomaly;
    const anomalies = [];
    for (const evt of sof_eof) {{
      const x = this.tsToX(evt.ts);
      let anomaly = false;
      if (evt.type === 'SOF') {{
        if (state !== 'high') {{
          d += ` L${{x}},${{lowY}} L${{x}},${{highY}}`;
          state = 'high';
        }} else {{
          anomaly = true; // SOF without preceding EOF
        }}
      }} else {{
        if (state !== 'low') {{
          d += ` L${{x}},${{highY}} L${{x}},${{lowY}}`;
          state = 'low';
        }} else {{
          anomaly = true; // EOF without preceding SOF
        }}
      }}
      anomalies.push(anomaly);
    }}
    // Extend to end
    const endX = MARGIN_L + this.plotWidth;
    d += ` L${{endX}},${{state === 'high' ? highY : lowY}}`;

    const path = this._ns('path');
    path.setAttribute('d', d);
    path.setAttribute('stroke', color);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke-width', 1.5);
    this.svg.appendChild(path);

    // Draw circles at edges; anomalous events get a warning arrow (SOF↑, EOF↓)
    // in #ff4500 — reserved color, never used by the measurement palette.
    // SOF+EOF collisions get a prominent red box + flash.
    sof_eof.forEach((evt, i) => {{
      const x = this.tsToX(evt.ts);
      const cy = evt.type === 'SOF' ? highY : lowY;
      const isCollision = evt.extra && evt.extra.includes('SOF+EOF COLLISION');

      if (isCollision) {{
        // Draw prominent error marker: red pulsing box spanning full lane height
        const box = this._ns('rect');
        box.setAttribute('x', x - 12); box.setAttribute('y', highY - 5);
        box.setAttribute('width', 24); box.setAttribute('height', lowY - highY + 10);
        box.setAttribute('fill', '#ff000022'); box.setAttribute('stroke', '#ff0000');
        box.setAttribute('stroke-width', 2.5);
        const anim = this._ns('animate');
        anim.setAttribute('attributeName', 'opacity');
        anim.setAttribute('values', '1;0.4;1'); anim.setAttribute('dur', '1s');
        anim.setAttribute('repeatCount', 'indefinite');
        box.appendChild(anim);
        this.svg.appendChild(box);

        // Red "!" exclamation inside
        const bang = this._ns('text');
        bang.setAttribute('x', x); bang.setAttribute('y', (highY + lowY) / 2 + 4);
        bang.setAttribute('text-anchor', 'middle'); bang.setAttribute('fill', '#ff0000');
        bang.setAttribute('font-size', 14); bang.setAttribute('font-weight', 'bold');
        bang.textContent = '!';
        this.svg.appendChild(bang);

        // Error label above
        const errLabel = this._ns('text');
        errLabel.setAttribute('x', x); errLabel.setAttribute('y', highY - 10);
        errLabel.setAttribute('text-anchor', 'middle'); errLabel.setAttribute('fill', '#ff0000');
        errLabel.setAttribute('font-size', 9); errLabel.setAttribute('font-weight', 'bold');
        errLabel.textContent = 'SOF+EOF!!';
        this.svg.appendChild(errLabel);

        evt._anomaly = 'SOF and EOF arrived simultaneously — sensor/CSID out of sync!';
      }}

      const c = this._ns('circle');
      c.setAttribute('cx', x); c.setAttribute('cy', cy);
      c.setAttribute('r', isCollision ? 5 : 3);
      c.setAttribute('fill', isCollision ? '#ff0000' : color);
      c.setAttribute('opacity', 0.9);
      this.svg.appendChild(c);

      if (anomalies[i] && !isCollision) {{
        // Hollow + dashed = "this transition is missing/inferred"
        const arrow = this._ns('polygon');
        const points = evt.type === 'SOF'
          ? `${{x}},${{cy - 11}} ${{x - 4}},${{cy - 4}} ${{x + 4}},${{cy - 4}}`
          : `${{x}},${{cy + 11}} ${{x - 4}},${{cy + 4}} ${{x + 4}},${{cy + 4}}`;
        arrow.setAttribute('points', points);
        arrow.setAttribute('fill', 'none');
        arrow.setAttribute('stroke', '#ff4500');
        arrow.setAttribute('stroke-width', 1.2);
        arrow.setAttribute('stroke-dasharray', '2,1.5');
        arrow.setAttribute('pointer-events', 'all');
        const missing = evt.type === 'SOF' ? 'EOF' : 'SOF';
        const t = this._ns('title');
        t.textContent = `Missing ${{missing}} before this ${{evt.type}}`;
        arrow.appendChild(t);
        this.svg.appendChild(arrow);
        evt._anomaly = `Missing ${{missing}} before this ${{evt.type}}`;
      }}
    }});

    // Frame labels (only for IPP_0)
    if (pathFilter === 'IPP_0') {{
      const sofs = sof_eof.filter(e => e.type === 'SOF');
      const step = Math.max(1, Math.floor(sofs.length / 30));
      sofs.forEach((evt, i) => {{
        if (i % step === 0 && evt.frame >= 0) {{
          const x = this.tsToX(evt.ts);
          this._text(x, highY - 3, 'F' + evt.frame, '#555', 9).setAttribute('text-anchor', 'middle');
        }}
      }});
    }}
  }}

  _drawMarkerLane(laneName, midY, vs, ve) {{
    const evts = this.events.filter(e => e.type === laneName && e.ts >= vs && e.ts <= ve);
    const color = COLORS[laneName];

    for (const evt of evts) {{
      const x = this.tsToX(evt.ts);
      if (laneName === 'RUP') {{
        const r = this._ns('rect');
        r.setAttribute('x', x - 1.5); r.setAttribute('y', midY - 10);
        r.setAttribute('width', 3); r.setAttribute('height', 20);
        r.setAttribute('fill', color); r.setAttribute('opacity', 0.85);
        this.svg.appendChild(r);
      }} else if (laneName === 'EPOCH0') {{
        const p = this._ns('polygon');
        p.setAttribute('points', `${{x}},${{midY-8}} ${{x+5}},${{midY}} ${{x}},${{midY+8}} ${{x-5}},${{midY}}`);
        p.setAttribute('fill', color); p.setAttribute('opacity', 0.85);
        this.svg.appendChild(p);
      }} else if (laneName === 'EPOCH1') {{
        const p = this._ns('polygon');
        p.setAttribute('points', `${{x}},${{midY-8}} ${{x+5}},${{midY}} ${{x}},${{midY+8}} ${{x-5}},${{midY}}`);
        p.setAttribute('fill', 'none'); p.setAttribute('stroke', color);
        p.setAttribute('stroke-width', 1.5); p.setAttribute('opacity', 0.85);
        this.svg.appendChild(p);
      }} else if (laneName === 'BUF_DONE') {{
        const pts = [];
        for (let k = 0; k < 10; k++) {{
          const angle = Math.PI/2 + k * Math.PI/5;
          const r = k % 2 === 0 ? 7 : 3.5;
          pts.push(`${{x + r*Math.cos(angle)}},${{midY - r*Math.sin(angle)}}`);
        }}
        const p = this._ns('polygon');
        p.setAttribute('points', pts.join(' '));
        p.setAttribute('fill', color); p.setAttribute('opacity', 0.85);
        this.svg.appendChild(p);
      }}
    }}
  }}

  _drawTimeAxis() {{
    const axisY = this.lanes.length * (LANE_H + LANE_GAP) + MARGIN_T + 5;
    const al = this._ns('line');
    al.setAttribute('x1', MARGIN_L); al.setAttribute('x2', MARGIN_L + this.plotWidth);
    al.setAttribute('y1', axisY); al.setAttribute('y2', axisY);
    al.setAttribute('stroke', '#444'); al.setAttribute('stroke-width', 1);
    this.svg.appendChild(al);

    const viewRange = this.view_end - this.view_start;
    // Choose nice tick interval
    const rawInterval = viewRange / 10;
    const mag = Math.pow(10, Math.floor(Math.log10(rawInterval)));
    const norm = rawInterval / mag;
    let interval;
    if (norm < 1.5) interval = mag;
    else if (norm < 3.5) interval = 2 * mag;
    else if (norm < 7.5) interval = 5 * mag;
    else interval = 10 * mag;

    const firstTick = Math.ceil(this.view_start / interval) * interval;
    for (let t = firstTick; t <= this.view_end; t += interval) {{
      const x = this.tsToX(t);
      const tick = this._ns('line');
      tick.setAttribute('x1', x); tick.setAttribute('x2', x);
      tick.setAttribute('y1', axisY); tick.setAttribute('y2', axisY + 4);
      tick.setAttribute('stroke', '#555');
      this.svg.appendChild(tick);

      const rel = t - this.t_min;
      let label;
      if (viewRange < 10) label = rel.toFixed(3) + 'ms';
      else if (viewRange < 100) label = rel.toFixed(2) + 'ms';
      else if (viewRange < 1000) label = rel.toFixed(1) + 'ms';
      else label = rel.toFixed(0) + 'ms';
      this._text(x, axisY + 15, label, '#666', 9).setAttribute('text-anchor', 'middle');

      // Vertical grid line
      const gl = this._ns('line');
      gl.setAttribute('x1', x); gl.setAttribute('x2', x);
      gl.setAttribute('y1', MARGIN_T); gl.setAttribute('y2', axisY);
      gl.setAttribute('stroke', '#1a1a3a'); gl.setAttribute('stroke-width', 0.5);
      this.svg.appendChild(gl);
    }}
  }}
}}

// (measurement history is managed per-view, no global measureHistory needed)

// Global view registry
const allViews = [];
let syncZoomEnabled = false;
let measureEnabled = false;
let mergedView = null;

document.getElementById('btn-measure').addEventListener('click', function() {{
  measureEnabled = !measureEnabled;
  this.textContent = measureEnabled ? '📏 Measure: ON' : '📏 Measure: OFF';
  this.style.background = measureEnabled ? '#2a4a3a' : '#2a2a4a';
  const allV = [...allViews, ...(mergedViewInstance ? [mergedViewInstance] : [])];
  for (const v of allV) {{
    v.measureStart = null;
    v._clearStartMarker();
    v.container.style.outline = '';
    // Ensure panel exists
    if (!v._measurePanel) v._initMeasurePanel();
    v._measurePanel.style.display = measureEnabled ? 'block' : 'none';
    if (!measureEnabled) {{
      v.measurements.forEach(m => m.visible = false);
    }} else {{
      v.measurements.forEach(m => m.visible = true);
    }}
    v.render();
  }}
}});

let mergedViewInstance = null;

// Build individual pipeline views
const pipelinesDiv = document.createElement('div');
pipelinesDiv.id = 'pipelines-container';
document.body.appendChild(pipelinesDiv);

Object.entries(PIPELINES).forEach(([key, data]) => {{
  const stats = STATS[key];
  const div = document.createElement('div');
  div.className = 'pipeline';
  div.dataset.pipeKey = key;

  let modeStr = stats.is_2exp ? `<b>${{stats.ipp_paths.length}}EXP (sHDR)</b> paths: ${{stats.ipp_paths.join(', ')}}` : '<b>1EXP</b>';

  // Build lane/path toggle checkboxes
  const allLanes = ['FRAME', 'RUP', 'EPOCH0', 'EPOCH1', 'BUF_DONE'];
  const laneColors = {{'FRAME':'#4ec9b0','RUP':'#569cd6','EPOCH0':'#dcdcaa','EPOCH1':'#d4be98','BUF_DONE':'#c586c0'}};
  const pathColors = {{'IPP_0':'#4ec9b0','IPP_1':'#9cdcfe','IPP_2':'#b8a0d4'}};
  let togglesHtml = '<div class="lane-toggles">';
  togglesHtml += '<span class="toggle-label">Lanes:</span>';
  allLanes.forEach(l => {{
    togglesHtml += `<label class="toggle-cb"><input type="checkbox" checked data-lane="${{l}}"><span style="color:${{laneColors[l]}}">${{l}}</span></label>`;
  }});
  if (data.ipp_paths.length > 1) {{
    togglesHtml += '<span class="toggle-sep">|</span><span class="toggle-label">Paths:</span>';
    data.ipp_paths.forEach(p => {{
      togglesHtml += `<label class="toggle-cb"><input type="checkbox" checked data-path="${{p}}"><span style="color:${{pathColors[p] || '#aaa'}}">${{p}}</span></label>`;
    }});
  }}
  togglesHtml += '</div>';

  div.innerHTML = `<h3>Pipeline: ${{key}}</h3>
    <div class="stats">${{modeStr}} | SOF-SOF: ${{stats.avg_period_ms}}ms (~${{stats.fps}} fps) | Events: ${{stats.num_events}}</div>
    ${{togglesHtml}}
    <div class="svg-container"></div>`;
  pipelinesDiv.appendChild(div);

  const container = div.querySelector('.svg-container');
  container.style.width = '100%';
  container.style.height = (5 * (LANE_H + LANE_GAP) + 50) + 'px';

  const view = new TimingView(container, key, data);
  allViews.push(view);

  // Bind lane toggles
  div.querySelectorAll('input[data-lane]').forEach(cb => {{
    cb.addEventListener('change', () => {{
      const lane = cb.dataset.lane;
      if (cb.checked) view.visibleLanes.add(lane);
      else view.visibleLanes.delete(lane);
      view.render();
    }});
  }});
  // Bind path toggles
  div.querySelectorAll('input[data-path]').forEach(cb => {{
    cb.addEventListener('change', () => {{
      const path = cb.dataset.path;
      if (cb.checked) view.visiblePaths.add(path);
      else view.visiblePaths.delete(path);
      view.render();
    }});
  }});
}});

// --- Sync Zoom ---
let globalTimeMin = Infinity, globalTimeMax = -Infinity;
for (const v of allViews) {{
  globalTimeMin = Math.min(globalTimeMin, v.t_min);
  globalTimeMax = Math.max(globalTimeMax, v.t_max);
}}

function syncAllViews(sourceView) {{
  if (!syncZoomEnabled) return;
  for (const v of allViews) {{
    if (v === sourceView) continue;
    v.view_start = sourceView.view_start;
    v.view_end = sourceView.view_end;
    v.render();
  }}
}}

// Patch each view to use global clamp bounds when synced, and broadcast changes
for (const v of allViews) {{
  const origContainer = v.container;
  origContainer.addEventListener('wheel', () => setTimeout(() => syncAllViews(v), 0));
  origContainer.addEventListener('mouseup', () => setTimeout(() => syncAllViews(v), 0));
}}

document.getElementById('btn-sync-zoom').addEventListener('click', function() {{
  syncZoomEnabled = !syncZoomEnabled;
  this.textContent = syncZoomEnabled ? '🔗 Sync Zoom: ON' : '🔗 Sync Zoom: OFF';
  this.style.background = syncZoomEnabled ? '#2a5a3a' : '#2a2a4a';

  if (syncZoomEnabled && allViews.length > 1) {{
    // Align all views: use global time range so absolute time positions match
    for (const v of allViews) {{
      v.t_min = globalTimeMin;
      v.t_max = globalTimeMax;
      v.view_start = globalTimeMin;
      v.view_end = globalTimeMax;
      v.render();
    }}
  }} else {{
    // Restore each view's own time range
    for (const v of allViews) {{
      const ts_list = v.events.map(e => e.ts);
      v.t_min = Math.min(...ts_list);
      v.t_max = Math.max(...ts_list);
      v.view_start = v.t_min;
      v.view_end = v.t_max;
      v.render();
    }}
  }}
}});

// --- Merge View button ---
document.getElementById('btn-merge-view').addEventListener('click', function() {{
  const mergeContainer = document.getElementById('merged-container');
  if (mergeContainer.style.display === 'block') {{
    // Toggle off
    mergeContainer.style.display = 'none';
    pipelinesDiv.style.display = 'block';
    this.textContent = '⊞ Merge View';
    this.style.background = '#2a2a4a';
    return;
  }}

  // Toggle on: build merged view
  pipelinesDiv.style.display = 'none';
  mergeContainer.style.display = 'block';
  mergeContainer.innerHTML = '';
  this.textContent = '⊞ Merge View: ON';
  this.style.background = '#2a4a5a';

  // Combine all events from all pipelines, tagging each with its pipeline key
  const mergedEvents = [];
  Object.entries(PIPELINES).forEach(([key, data]) => {{
    for (const e of data.events) {{
      mergedEvents.push({{ ...e, pipeKey: key }});
    }}
  }});
  mergedEvents.sort((a, b) => a.ts - b.ts);

  // Group by lane type, then by pipeline within each lane
  const pipeKeys = Object.keys(PIPELINES);
  const laneTypes = ['FRAME', 'RUP', 'EPOCH0', 'EPOCH1', 'BUF_DONE'];
  const numSubLanes = pipeKeys.length;
  const subLaneH = Math.max(30, Math.floor(50 / numSubLanes));
  const mergedLaneH = subLaneH * numSubLanes + 10;
  const mergedSvgH = laneTypes.length * (mergedLaneH + LANE_GAP) + 50;

  // Assign colors per pipeline
  const pipeColors = ['#4ec9b0', '#e06c75', '#61afef', '#d19a66', '#98c379'];

  const svgCont = document.createElement('div');
  svgCont.className = 'svg-container';
  svgCont.style.width = '100%';
  svgCont.style.height = mergedSvgH + 'px';
  mergeContainer.appendChild(svgCont);

  // Build merged data structure
  const mergedData = {{
    ctx: -1, link: 'merged',
    events: mergedEvents,
    is_2exp: false,
    ipp_paths: ['IPP_0'],
  }};

  // Create a special merged TimingView
  class MergedTimingView extends TimingView {{
    constructor(container, data, pipeKeys, pipeColors) {{
      super(container, 'merged', data, {{skipInitRender: true}});
      this.pipeKeys = pipeKeys;
      this.pipeColors = pipeColors;
      this.lanes = laneTypes;
      this.subLaneH = subLaneH;
      this.mergedLaneH = mergedLaneH;
      this.svgHeight = mergedSvgH;
      this.svg.setAttribute('height', mergedSvgH);
      this.render();
    }}

    render() {{
      while (this.svg.firstChild) this.svg.removeChild(this.svg.firstChild);
      this.svg.appendChild(this.crossV);
      this.svg.appendChild(this.crossH);
      this.svg.appendChild(this.timeLabel);

      const vs = this.view_start, ve = this.view_end;

      for (let li = 0; li < this.lanes.length; li++) {{
        const laneName = this.lanes[li];
        const laneTop = li * (this.mergedLaneH + LANE_GAP) + MARGIN_T;

        // Lane label
        this._text(5, laneTop + this.mergedLaneH / 2, laneName, '#778', 11);

        // Per-pipeline sub-lanes
        this.pipeKeys.forEach((pk, pi) => {{
          const color = this.pipeColors[pi % this.pipeColors.length];
          const sTop = laneTop + pi * this.subLaneH;
          const sBot = sTop + this.subLaneH - 2;
          const sMid = (sTop + sBot) / 2;

          // Sub-lane label (short)
          const shortLabel = pk.split(',')[0]; // "ctx=3"
          this._text(MARGIN_L - 5, sMid + 3, shortLabel, color, 8).setAttribute('text-anchor', 'end');

          // Separator line
          const sep = this._ns('line');
          sep.setAttribute('x1', MARGIN_L); sep.setAttribute('x2', MARGIN_L + this.plotWidth);
          sep.setAttribute('y1', sBot + 1); sep.setAttribute('y2', sBot + 1);
          sep.setAttribute('stroke', '#1a1a2a'); sep.setAttribute('stroke-width', 0.5);
          this.svg.appendChild(sep);

          if (laneName === 'FRAME') {{
            // Draw square wave for this pipeline
            const pipeEvts = this.events.filter(e =>
              e.pipeKey === pk && (e.type === 'SOF' || e.type === 'EOF') &&
              e.extra.includes('IPP_0') && e.ts >= vs && e.ts <= ve
            );
            if (pipeEvts.length > 0) {{
              const allBefore = this.events.filter(e =>
                e.pipeKey === pk && (e.type === 'SOF' || e.type === 'EOF') &&
                e.extra.includes('IPP_0') && e.ts < vs
              );
              let state = 'low';
              for (const e of allBefore) {{
                if (e.type === 'SOF' && state !== 'high') state = 'high';
                else if (e.type === 'EOF' && state !== 'low') state = 'low';
              }}

              let d = `M${{MARGIN_L}},${{state === 'high' ? sTop : sBot}}`;
              for (const evt of pipeEvts) delete evt._anomaly;
              const anomalies = [];
              for (const evt of pipeEvts) {{
                const x = this.tsToX(evt.ts);
                let anomaly = false;
                if (evt.type === 'SOF') {{
                  if (state !== 'high') {{ d += ` L${{x}},${{sBot}} L${{x}},${{sTop}}`; state = 'high'; }}
                  else anomaly = true;
                }} else {{
                  if (state !== 'low') {{ d += ` L${{x}},${{sTop}} L${{x}},${{sBot}}`; state = 'low'; }}
                  else anomaly = true;
                }}
                anomalies.push(anomaly);
              }}
              d += ` L${{MARGIN_L + this.plotWidth}},${{state === 'high' ? sTop : sBot}}`;
              const path = this._ns('path');
              path.setAttribute('d', d); path.setAttribute('stroke', color);
              path.setAttribute('fill', 'none'); path.setAttribute('stroke-width', 1.5);
              this.svg.appendChild(path);
              // Mark anomalous events and SOF+EOF collisions
              pipeEvts.forEach((evt, i) => {{
                const x = this.tsToX(evt.ts);
                const cy = evt.type === 'SOF' ? sTop : sBot;
                const isCollision = evt.extra && evt.extra.includes('SOF+EOF COLLISION');

                if (isCollision) {{
                  const box = this._ns('rect');
                  box.setAttribute('x', x - 8); box.setAttribute('y', sTop - 3);
                  box.setAttribute('width', 16); box.setAttribute('height', sBot - sTop + 6);
                  box.setAttribute('fill', '#ff000022'); box.setAttribute('stroke', '#ff0000');
                  box.setAttribute('stroke-width', 2);
                  const anim = this._ns('animate');
                  anim.setAttribute('attributeName', 'opacity');
                  anim.setAttribute('values', '1;0.4;1'); anim.setAttribute('dur', '1s');
                  anim.setAttribute('repeatCount', 'indefinite');
                  box.appendChild(anim);
                  this.svg.appendChild(box);
                  evt._anomaly = 'SOF and EOF arrived simultaneously — sensor/CSID out of sync!';
                }} else if (anomalies[i]) {{
                  const arrow = this._ns('polygon');
                  const points = evt.type === 'SOF'
                    ? `${{x}},${{cy - 9}} ${{x - 3}},${{cy - 3}} ${{x + 3}},${{cy - 3}}`
                    : `${{x}},${{cy + 9}} ${{x - 3}},${{cy + 3}} ${{x + 3}},${{cy + 3}}`;
                  arrow.setAttribute('points', points);
                  arrow.setAttribute('fill', 'none');
                  arrow.setAttribute('stroke', '#ff4500');
                  arrow.setAttribute('stroke-width', 1.2);
                  arrow.setAttribute('stroke-dasharray', '2,1.5');
                  arrow.setAttribute('pointer-events', 'all');
                  const missing = evt.type === 'SOF' ? 'EOF' : 'SOF';
                  const t = this._ns('title');
                  t.textContent = `Missing ${{missing}} before this ${{evt.type}}`;
                  arrow.appendChild(t);
                  this.svg.appendChild(arrow);
                  evt._anomaly = `Missing ${{missing}} before this ${{evt.type}}`;
                }}
              }});
            }}
          }} else {{
            // Markers for this pipeline in this lane
            const pipeEvts = this.events.filter(e =>
              e.pipeKey === pk && e.type === laneName && e.ts >= vs && e.ts <= ve
            );
            for (const evt of pipeEvts) {{
              const x = this.tsToX(evt.ts);
              if (laneName === 'RUP') {{
                const r = this._ns('rect');
                r.setAttribute('x', x-1); r.setAttribute('y', sMid-7);
                r.setAttribute('width', 2); r.setAttribute('height', 14);
                r.setAttribute('fill', color); r.setAttribute('opacity', 0.85);
                this.svg.appendChild(r);
              }} else if (laneName === 'EPOCH0') {{
                const p = this._ns('polygon');
                p.setAttribute('points', `${{x}},${{sMid-6}} ${{x+4}},${{sMid}} ${{x}},${{sMid+6}} ${{x-4}},${{sMid}}`);
                p.setAttribute('fill', color); p.setAttribute('opacity', 0.85);
                this.svg.appendChild(p);
              }} else if (laneName === 'EPOCH1') {{
                const p = this._ns('polygon');
                p.setAttribute('points', `${{x}},${{sMid-6}} ${{x+4}},${{sMid}} ${{x}},${{sMid+6}} ${{x-4}},${{sMid}}`);
                p.setAttribute('fill', 'none'); p.setAttribute('stroke', color);
                p.setAttribute('stroke-width', 1.2); p.setAttribute('opacity', 0.85);
                this.svg.appendChild(p);
              }} else if (laneName === 'BUF_DONE') {{
                const pts = [];
                for (let k = 0; k < 10; k++) {{
                  const angle = Math.PI/2 + k * Math.PI/5;
                  const r = k%2===0 ? 5 : 2.5;
                  pts.push(`${{x+r*Math.cos(angle)}},${{sMid-r*Math.sin(angle)}}`);
                }}
                const p = this._ns('polygon');
                p.setAttribute('points', pts.join(' '));
                p.setAttribute('fill', color); p.setAttribute('opacity', 0.85);
                this.svg.appendChild(p);
              }}
            }}
          }}
        }});
      }}
      this._drawTimeAxis();
      this._drawMeasurements();
      if (this.measureStart) this._drawStartMarker(this.measureStart);
    }}

    _getLaneAtY(my) {{
      for (let li = 0; li < this.lanes.length; li++) {{
        const laneTop = li * (this.mergedLaneH + LANE_GAP) + MARGIN_T;
        if (my >= laneTop && my < laneTop + this.mergedLaneH) return this.lanes[li];
      }}
      return null;
    }}

    _getEvtY(evt) {{
      const laneName = (evt.type === 'SOF' || evt.type === 'EOF') ? 'FRAME' : evt.type;
      const li = this.lanes.indexOf(laneName);
      if (li < 0) return -1;
      const laneTop = li * (this.mergedLaneH + LANE_GAP) + MARGIN_T;
      const pi = this.pipeKeys.indexOf(evt.pipeKey);
      if (pi < 0) return laneTop + this.mergedLaneH / 2;
      const sTop = laneTop + pi * this.subLaneH;
      const sBot = sTop + this.subLaneH - 2;
      if (evt.type === 'SOF') return sTop;
      if (evt.type === 'EOF') return sBot;
      return (sTop + sBot) / 2;
    }}

    _drawTimeAxis() {{
      const axisY = this.lanes.length * (this.mergedLaneH + LANE_GAP) + MARGIN_T + 5;
      const al = this._ns('line');
      al.setAttribute('x1', MARGIN_L); al.setAttribute('x2', MARGIN_L + this.plotWidth);
      al.setAttribute('y1', axisY); al.setAttribute('y2', axisY);
      al.setAttribute('stroke', '#444'); al.setAttribute('stroke-width', 1);
      this.svg.appendChild(al);

      const viewRange = this.view_end - this.view_start;
      const rawInterval = viewRange / 10;
      const mag = Math.pow(10, Math.floor(Math.log10(rawInterval)));
      const norm = rawInterval / mag;
      let interval;
      if (norm < 1.5) interval = mag;
      else if (norm < 3.5) interval = 2*mag;
      else if (norm < 7.5) interval = 5*mag;
      else interval = 10*mag;

      const firstTick = Math.ceil(this.view_start / interval) * interval;
      for (let t = firstTick; t <= this.view_end; t += interval) {{
        const x = this.tsToX(t);
        const tick = this._ns('line');
        tick.setAttribute('x1', x); tick.setAttribute('x2', x);
        tick.setAttribute('y1', axisY); tick.setAttribute('y2', axisY+4);
        tick.setAttribute('stroke', '#555'); this.svg.appendChild(tick);

        const rel = t - this.t_min;
        let label;
        if (viewRange < 10) label = rel.toFixed(3)+'ms';
        else if (viewRange < 100) label = rel.toFixed(2)+'ms';
        else if (viewRange < 1000) label = rel.toFixed(1)+'ms';
        else label = rel.toFixed(0)+'ms';
        this._text(x, axisY+15, label, '#666', 9).setAttribute('text-anchor','middle');

        const gl = this._ns('line');
        gl.setAttribute('x1', x); gl.setAttribute('x2', x);
        gl.setAttribute('y1', MARGIN_T); gl.setAttribute('y2', axisY);
        gl.setAttribute('stroke', '#1a1a3a'); gl.setAttribute('stroke-width', 0.5);
        this.svg.appendChild(gl);
      }}
    }}
  }}

  // Pipeline color legend for merged view
  const legendDiv = document.createElement('div');
  legendDiv.className = 'legend';
  legendDiv.style.marginBottom = '8px';
  pipeKeys.forEach((pk, pi) => {{
    const c = pipeColors[pi % pipeColors.length];
    legendDiv.innerHTML += `<div class="legend-item"><span style="color:${{c}};font-size:16px">●</span><span>${{pk}}</span></div>`;
  }});
  mergeContainer.insertBefore(legendDiv, svgCont);

  // Use requestAnimationFrame to ensure layout is computed before reading clientWidth
  requestAnimationFrame(() => {{
    mergedViewInstance = new MergedTimingView(svgCont, mergedData, pipeKeys, pipeColors);
    // If measure mode is already on, init the panel immediately
    if (measureEnabled) {{
      mergedViewInstance._initMeasurePanel();
      mergedViewInstance._measurePanel.style.display = 'block';
    }}
  }});
}});
</script>
</body></html>'''

    return html



def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(
        description='ISP Timing Diagram Generator - Parse camera kernel logs '
                    'and generate timing diagrams for ISP HW events.')
    parser.add_argument('logfile', help='Path to the kernel log file')
    parser.add_argument('--ctx', type=int, default=None,
                        help='Filter by context index')
    parser.add_argument('--link', type=str, default=None,
                        help='Filter by link handle (e.g., 0xa6031a)')
    parser.add_argument('--csid-path', type=str, default=None,
                        help='Filter SOF/EOF by CSID path (e.g., IPP_0, IPP_1). '
                             'Only IPP_0 SOF/EOF define frame boundaries by default.')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--width', type=int, default=130,
                        help='Maximum output width (default: 130)')
    parser.add_argument('--mode', choices=['detail', 'waveform', 'both', 'html'],
                        default='both',
                        help='Output mode: detail, waveform, both, or html (default: both)')
    parser.add_argument('--output', '-o', type=str, default=None,
                        help='Output file (default: stdout)')

    args = parser.parse_args()
    use_color = not args.no_color

    # If output to file, disable color by default
    if args.output:
        use_color = False

    print(f"Parsing log file: {args.logfile}")
    events, ctx_ipp_paths = parse_log(args.logfile, ctx_filter=args.ctx,
                                      link_filter=args.link,
                                      csid_path_filter=args.csid_path)
    print(f"Found {len(events)} events")

    # Validate SOF/EOF pairing and associate SOF with RUP/EPOCH
    events = validate_and_associate_events(events)
    orphan_eofs = [e for e in events if '!!ORPHAN_EOF!!' in e.extra]
    missing_eofs = [e for e in events if '!!MISSING_EOF!!' in e.extra]
    if orphan_eofs:
        print(f"  WARNING: {len(orphan_eofs)} EOF(s) without prior SOF")
    if missing_eofs:
        print(f"  WARNING: {len(missing_eofs)} SOF(s) without subsequent EOF")

    # Report exposure mode per context
    for ctx_id, paths in sorted(ctx_ipp_paths.items()):
        if len(paths) > 1:
            print(f"  ctx={ctx_id}: {len(paths)}EXP detected (paths: {', '.join(sorted(paths))})")
        else:
            print(f"  ctx={ctx_id}: 1EXP (path: {', '.join(sorted(paths))})")

    if not events:
        print("No ISP events found in the log file.")
        print("Make sure the log contains CAM-ISP debug messages with "
              "CSID path_top_half or IRQ handler entries.")
        sys.exit(1)

    output = ""
    if args.mode == 'html':
        import os
        output = generate_html_timing(events, max_width=args.width,
                                      ctx_ipp_paths=ctx_ipp_paths,
                                      filename=os.path.basename(args.logfile))
        # Default output to .html file
        if not args.output:
            args.output = args.logfile.rsplit('.', 1)[0] + '_timing.html'
    else:
        if args.mode in ('detail', 'both'):
            output += generate_timing_diagram(events, use_color=use_color,
                                              max_width=args.width)
        if args.mode in ('waveform', 'both'):
            output += "\n\n"
            output += generate_ascii_waveform(events, use_color=use_color,
                                              max_width=args.width)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Output written to: {args.output}")
    else:
        print(output)


if __name__ == '__main__':
    main()
