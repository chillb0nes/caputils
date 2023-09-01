from __future__ import annotations

import contextlib
import gzip
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

import dpkt


@contextlib.contextmanager
def pcap_reader(path: str | Path) -> dpkt.pcap.Reader | dpkt.pcapng.Reader:
    if isinstance(path, str):
        path = Path(path)

    try:
        with gzip.open(path, "rb") as tmp:
            tmp.read(1)
        fd = gzip.open(path, "rb")
    except gzip.BadGzipFile:
        fd = path.open("rb")

    try:
        yield dpkt.pcap.Reader(fd)
    except ValueError:
        fd.seek(0, 0)
        yield dpkt.pcapng.Reader(fd)
    finally:
        fd.close()


def capinfos(
    path: str | Path | list[str] | list[Path], *opts: str
) -> dict[str, str] | list[dict[str, str]]:
    if isinstance(path, list):
        if len(path) == 0:
            raise RuntimeError("No paths provided")

        paths = path
    else:
        paths = [path]

    if not all(opt.startswith("-") for opt in opts):
        raise RuntimeError("All opts must start with '-'")

    if "-T" not in opts:
        opts = [*opts, "-T"]
    if "-M" not in opts:
        opts = [*opts, "-M"]

    out = subprocess.check_output(["capinfos", *opts, *paths], universal_newlines=True)
    if not out or len(out.splitlines()) < 2 or "\t" not in out:
        raise RuntimeError(f"Unexpected output format of capinfos command:\n{out}")

    infos = []

    lines = out.splitlines()
    keys = lines[0].split("\t")
    for line in lines[1:]:
        values = line.split("\t")
        info = {k: v for k, v in zip(keys, values)}
        infos.append(info)

    if len(infos) > 1:
        return infos
    else:
        return infos[0]


def count(path: str | Path) -> int:
    if not shutil.which("capinfos"):
        with pcap_reader(path) as reader:
            return sum(1 for _ in reader)

    ci = capinfos(path, "-c")
    return int(ci["Number of packets"])


def get_start_end(pcap: str | Path) -> (float, float):
    ci = capinfos(pcap, "-aeS")

    def parse(val: str) -> float:
        return float(val.replace(",", "."))

    start_seconds = parse(ci["Start time"])
    end_seconds = parse(ci["End time"])

    return start_seconds, end_seconds


def shift_time(
    infile: str | Path,
    outfile: str | Path,
    seconds: float = None,
    *,
    reference: str | Path = None,
    position: float = 0.0,
    filetype: Literal["pcap", "pcapng"] = "pcap",
):
    if seconds is not None:
        assert (
            reference is None and position is None
        ), "Seconds cannot be specified along with reference and position"
    else:
        assert (
            reference is not None and position is not None
        ), "Reference and position cannot be specified along with seconds"
        assert 0 <= position <= 1, "Position must be between 0 and 1"

        origin, _ = get_start_end(infile)
        start_seconds, end_seconds = get_start_end(reference)
        seconds = start_seconds + (end_seconds - start_seconds) * position - origin

    opts = ["-t", str(seconds), "-F", filetype]
    subprocess.check_call(["editcap", *opts, infile, outfile])


def mergecap(
    infiles: list[str | Path],
    outfile: str | Path,
    concat: bool = False,
    filetype: Literal["pcap", "pcapng"] = "pcap",
):
    opts = ["-w", outfile, "-F", filetype]
    if concat:
        opts.append("-a")
    subprocess.check_call(["mergecap", *opts, *infiles])


def merge_time_aligned(
    left: str | Path,
    right: str | Path,
    outfile: str | Path,
    filetype: Literal["pcap", "pcapng"] = "pcap",
):
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.close()
        right_shifted = tmp.name
        shift_time(right, right_shifted, reference=left)
        mergecap([left, right_shifted], outfile, filetype=filetype)
