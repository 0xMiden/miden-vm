"""Read bounded coverage data from an untrusted ZIP without extracting files."""

import io
import json
import sys
import zipfile

MAX_ARCHIVE = 10 * 1024 * 1024
MAX_REPORT = 60 * 1024


def read_coverage(data):
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Coverage archive exceeds size limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        result = {}
        for name, key, limit in (
            ("coverage-pr-context.txt", "context", 1024),
            ("coverage-comment.md", "report", MAX_REPORT),
        ):
            if name not in names:
                return None
            if names.count(name) != 1:
                raise ValueError("Duplicate coverage archive member")
            info = archive.getinfo(name)
            if info.file_size > limit or info.flag_bits & 1:
                raise ValueError("Oversized or encrypted coverage archive member")
            # Paths and member attributes never become filesystem operations.
            with archive.open(info) as member:
                result[key] = member.read(limit).decode("utf-8")
        return result


if __name__ == "__main__":
    json.dump(read_coverage(sys.stdin.buffer.read(MAX_ARCHIVE + 1)), sys.stdout)
