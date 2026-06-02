#!/usr/bin/env python3
"""Parse and filter btsnoop/Wireshark text exports.

This module is intentionally dependency-free and handles:
  * gzip-compressed or plain-text Wireshark/tshark text exports
  * frame summaries such as:
      1 2026-05-31 19:29:36.834925 host → controller HCI_CMD 4 Sent Reset
  * detailed per-frame fields, including Bluetooth source/destination, HCI packet type,
    opcodes/events, MAC-like Bluetooth addresses, and hex dump bytes.

Notes:
  * Classic btsnoop binary files can be converted to text first with tshark:
      tshark -r input.cfa -V -x > btsnoop.txt
  * The attached sample is a gzip-compressed text export, not a raw binary btsnoop file.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

SUMMARY_RE = re.compile(
    r"^\s*(?P<number>\d+)\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<source>.+?)\s+(?:→|->)\s+(?P<destination>.+?)\s+"
    r"(?P<packet_type>\S+)\s+(?P<length>\d+)\s+(?P<summary>.*)$"
)
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
HEX_DUMP_RE = re.compile(r"^\s*[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s+)+)")
FIELD_RE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_ .\-/()\[\]+&]+):\s*(?P<value>.+?)\s*$")

ADDRESS_KEYS = (
    "bd_addr",
    "address",
    "device address",
    "peer address",
    "advertising address",
    "initiator address",
    "scanner address",
    "source address",
    "destination address",
    "sender address",
    "receiver address",
)
SOURCE_ADDRESS_HINTS = ("source address", "sender address", "initiator address", "scanner address")
DEST_ADDRESS_HINTS = ("destination address", "receiver address", "peer address", "advertising address", "device address")


@dataclass(slots=True)
class Packet:
    number: int
    timestamp: datetime
    source: str
    destination: str
    packet_type: str
    length: int
    summary: str
    raw_text: str
    hci_packet_type: Optional[str] = None
    direction: Optional[str] = None
    opcode: Optional[str] = None
    event_code: Optional[str] = None
    status: Optional[str] = None
    addresses: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    payload_hex: str = ""

    def to_dict(self, include_raw: bool = False) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat(sep=" ")
        if not include_raw:
            d.pop("raw_text", None)
        return d


def _open_maybe_gzip(path: str | Path):
    path = Path(path)
    with path.open("rb") as fh:
        magic = fh.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("rt", encoding="utf-8", errors="replace")


def parse_datetime(value: str | datetime | None) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    text = value.strip()
    if not text:
        return None
    # Accept ISO strings and common CLI-friendly forms.
    text = text.replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return datetime.fromisoformat(text)


def _clean_key(key: str) -> str:
    return " ".join(key.strip().lower().split())


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        norm = value.lower()
        if norm not in seen:
            seen.add(norm)
            out.append(value.lower())
    return out


def _parse_packet(lines: list[str]) -> Packet:
    header = SUMMARY_RE.match(lines[0])
    if not header:
        raise ValueError(f"Not a packet header: {lines[0]!r}")

    gd = header.groupdict()
    packet = Packet(
        number=int(gd["number"]),
        timestamp=parse_datetime(f"{gd['date']} {gd['time']}") or datetime.min,
        source=gd["source"].strip(),
        destination=gd["destination"].strip(),
        packet_type=gd["packet_type"].strip(),
        length=int(gd["length"]),
        summary=gd["summary"].strip(),
        raw_text="\n".join(lines),
    )

    addresses: list[str] = []
    src_addrs: list[str] = []
    dst_addrs: list[str] = []
    payload_parts: list[str] = []

    for line in lines[1:]:
        m = FIELD_RE.match(line)
        if m:
            key = _clean_key(m.group("key"))
            value = m.group("value").strip()
            # Keep first instance under exact normalized key; duplicate Wireshark keys are common.
            packet.fields.setdefault(key, value)

            if key == "hci packet type":
                packet.hci_packet_type = value
            elif key == "direction":
                packet.direction = value
            elif key == "command opcode":
                packet.opcode = value
            elif key == "event code":
                packet.event_code = value
            elif key == "status":
                packet.status = value

            found = MAC_RE.findall(value)
            if found and any(addr_key in key for addr_key in ADDRESS_KEYS):
                addresses.extend(found)
                if any(hint in key for hint in SOURCE_ADDRESS_HINTS):
                    src_addrs.extend(found)
                if any(hint in key for hint in DEST_ADDRESS_HINTS):
                    dst_addrs.extend(found)

        # MACs may also appear in generated summary text lines.
        addresses.extend(MAC_RE.findall(line))

        hm = HEX_DUMP_RE.match(line)
        if hm:
            payload_parts.extend(hm.group(1).split())

    packet.addresses = _unique(addresses)
    packet.source_addresses = _unique(src_addrs)
    packet.destination_addresses = _unique(dst_addrs)
    packet.payload_hex = "".join(payload_parts).lower()
    return packet


def iter_packets(path: str | Path) -> Iterator[Packet]:
    current: list[str] = []
    with _open_maybe_gzip(path) as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            if SUMMARY_RE.match(line):
                if current:
                    yield _parse_packet(current)
                current = [line]
            elif current:
                current.append(line)
    if current:
        yield _parse_packet(current)


def parse_file(path: str | Path) -> list[Packet]:
    return list(iter_packets(path))


def _matches_any(value: Optional[str], choices: Optional[Sequence[str]]) -> bool:
    if not choices:
        return True
    if value is None:
        return False
    value_l = value.lower()
    return any(choice.lower() in value_l for choice in choices)


def _addr_matches(actual: Sequence[str], requested: Optional[Sequence[str]]) -> bool:
    if not requested:
        return True
    actual_norm = {a.lower() for a in actual}
    for req in requested:
        req_l = req.lower()
        if req_l in actual_norm:
            return True
    return False


def filter_packets(
    packets: Iterable[Packet],
    *,
    from_mac: str | Sequence[str] | None = None,
    to_mac: str | Sequence[str] | None = None,
    any_mac: str | Sequence[str] | None = None,
    from_datetime: str | datetime | None = None,
    to_datetime: str | datetime | None = None,
    packet_type: str | Sequence[str] | None = None,
    source: str | Sequence[str] | None = None,
    destination: str | Sequence[str] | None = None,
    direction: str | Sequence[str] | None = None,
    text: str | None = None,
) -> list[Packet]:
    def listify(v):
        if v is None:
            return None
        if isinstance(v, str):
            return [v]
        return list(v)

    from_macs = listify(from_mac)
    to_macs = listify(to_mac)
    any_macs = listify(any_mac)
    packet_types = listify(packet_type)
    sources = listify(source)
    destinations = listify(destination)
    directions = listify(direction)
    start = parse_datetime(from_datetime)
    end = parse_datetime(to_datetime)
    text_l = text.lower() if text else None

    result: list[Packet] = []
    for p in packets:
        if start and p.timestamp < start:
            continue
        if end and p.timestamp > end:
            continue
        if not _matches_any(p.packet_type, packet_types) and not _matches_any(p.hci_packet_type, packet_types):
            continue
        if not _matches_any(p.source, sources):
            continue
        if not _matches_any(p.destination, destinations):
            continue
        if not _matches_any(p.direction, directions) and not _matches_any(p.summary, directions):
            continue
        if not _addr_matches(p.source_addresses, from_macs):
            continue
        if not _addr_matches(p.destination_addresses, to_macs):
            continue
        if not _addr_matches(p.addresses, any_macs):
            continue
        if text_l and text_l not in p.raw_text.lower() and text_l not in p.summary.lower():
            continue
        result.append(p)
    return result


def write_json(packets: Sequence[Packet], path: str | Path, include_raw: bool = False) -> None:
    data = [p.to_dict(include_raw=include_raw) for p in packets]
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_csv(packets: Sequence[Packet], path: str | Path) -> None:
    columns = [
        "number", "timestamp", "source", "destination", "packet_type", "length", "summary",
        "hci_packet_type", "direction", "opcode", "event_code", "status",
        "addresses", "source_addresses", "destination_addresses", "payload_hex",
    ]
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for p in packets:
            row = p.to_dict(include_raw=False)
            for key in ("addresses", "source_addresses", "destination_addresses"):
                row[key] = ";".join(row.get(key, []))
            writer.writerow({k: row.get(k, "") for k in columns})


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Parse/filter Wireshark btsnoop text exports, including .gz files.")
    ap.add_argument("input", help="Input btsnoop text export or .gz")
    ap.add_argument("--from-mac", action="append", help="Source Bluetooth MAC/address. Repeatable.")
    ap.add_argument("--to-mac", action="append", help="Destination Bluetooth MAC/address. Repeatable.")
    ap.add_argument("--any-mac", action="append", help="Any packet containing this Bluetooth MAC/address. Repeatable.")
    ap.add_argument("--from-datetime", help="Inclusive start, e.g. '2026-05-31 19:29:36.90'")
    ap.add_argument("--to-datetime", help="Inclusive end")
    ap.add_argument("--packet-type", action="append", help="Packet type substring, e.g. HCI_EVT, HCI_CMD, ACL, HCI Event")
    ap.add_argument("--source", action="append", help="Source endpoint substring, e.g. host/controller")
    ap.add_argument("--destination", action="append", help="Destination endpoint substring")
    ap.add_argument("--direction", action="append", help="Direction substring, e.g. Sent/Rcvd")
    ap.add_argument("--text", help="Free-text substring to search in packet details")
    ap.add_argument("--format", choices=("json", "csv", "summary"), default="summary")
    ap.add_argument("--output", "-o", help="Write json/csv output to this path. Summary prints to stdout.")
    ap.add_argument("--include-raw", action="store_true", help="Include raw packet text in JSON output.")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of printed/exported packets; 0 = no limit.")
    args = ap.parse_args(argv)

    packets = filter_packets(
        iter_packets(args.input),
        from_mac=args.from_mac,
        to_mac=args.to_mac,
        any_mac=args.any_mac,
        from_datetime=args.from_datetime,
        to_datetime=args.to_datetime,
        packet_type=args.packet_type,
        source=args.source,
        destination=args.destination,
        direction=args.direction,
        text=args.text,
    )
    if args.limit:
        packets = packets[: args.limit]

    if args.format == "json":
        if args.output:
            write_json(packets, args.output, include_raw=args.include_raw)
        else:
            print(json.dumps([p.to_dict(include_raw=args.include_raw) for p in packets], indent=2))
    elif args.format == "csv":
        if not args.output:
            raise SystemExit("--output is required for CSV output")
        write_csv(packets, args.output)
    else:
        for p in packets:
            addr = f" addresses={','.join(p.addresses)}" if p.addresses else ""
            print(f"{p.number:6d} {p.timestamp} {p.source} -> {p.destination} {p.packet_type:<8} {p.length:5d} {p.summary}{addr}")
        print(f"Matched {len(packets)} packet(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
