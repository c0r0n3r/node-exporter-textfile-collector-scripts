#!/usr/bin/env python3

"""
Description: Expose the expiry time of X.509 certificate files.

Only the files named on the command line are opened. Each one is read with
the openssl command, and a path whose name suggests a private key is refused
without being opened.

Every path named is published as certificate_readable, so a path that does
not exist, cannot be read or does not hold a certificate is reported as 0
rather than left out. A path that is silently skipped cannot be told apart
from a certificate that is not there, and its expiry would never be noticed.

The expiry is published as the Unix time of the certificate's notAfter, not
as the time left, so the value stays correct between runs:

    certificate_not_after_timestamp_seconds - time() < 21 * 86400

Usage:

    certificate_expiry.py /etc/ssl/example.crt /etc/ssl/other.crt \
        | sponge /var/lib/prometheus/node-exporter/certificate_expiry.prom

Dependencies: openssl, python3-prometheus-client

Author: Szilárd Pfeiffer
"""

import argparse
import datetime
import pathlib
import subprocess
import sys

import prometheus_client

# A path containing any of these is never opened, whatever the command line says.
KEY_NAME_MARKERS = (".key", "privkey", "private", "_key", "-key")

# With `-dateopt iso_8601`, `openssl x509 -enddate` prints `notAfter=2027-09-11 12:00:00Z`,
# which carries its own time zone and does not depend on month names.
OPENSSL_TIMEOUT_SECONDS = 20


def looks_like_a_key(path: str) -> bool:
    """Return whether the path's name suggests a private key.

    :param path: the path named on the command line
    :type path: str
    :returns: True if the path must not be opened
    :rtype: bool
    """
    lowered = path.lower()
    return any(marker in lowered for marker in KEY_NAME_MARKERS)


def read_not_after(path: str) -> float | None:
    """Return the certificate's notAfter as a Unix timestamp.

    :param path: the certificate file to read
    :type path: str
    :returns: the notAfter time, or None if the file cannot be read as a certificate
    :rtype: float or None
    """
    if looks_like_a_key(path) or not pathlib.Path(path).is_file():
        return None
    try:
        completed = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-enddate", "-dateopt", "iso_8601"],
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None

    _, _, value = completed.stdout.strip().partition("=")
    try:
        not_after = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if not_after.tzinfo is None:
        return None
    return not_after.timestamp()


def main() -> int:
    """Print the metrics for every path named on the command line.

    :returns: the exit status
    :rtype: int
    """
    parser = argparse.ArgumentParser(
        description="Expose the expiry time of X.509 certificate files."
    )
    parser.add_argument("paths", nargs="+", metavar="PATH", help="a certificate file to read")
    arguments = parser.parse_args()

    registry = prometheus_client.CollectorRegistry()
    readable = prometheus_client.Gauge(
        "certificate_readable",
        "Whether the certificate file could be read and parsed.",
        ["path"],
        registry=registry,
    )
    not_after = prometheus_client.Gauge(
        "certificate_not_after_timestamp_seconds",
        "Unix time of the certificate's notAfter.",
        ["path"],
        registry=registry,
    )

    for path in arguments.paths:
        timestamp = read_not_after(path)
        readable.labels(path).set(0 if timestamp is None else 1)
        if timestamp is not None:
            not_after.labels(path).set(timestamp)

    sys.stdout.write(prometheus_client.generate_latest(registry).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
