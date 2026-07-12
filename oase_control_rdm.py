#!/usr/bin/env python3
"""Backward-compatible command-line entry point for OASE control."""

from oase_fm import main


if __name__ == "__main__":
    raise SystemExit(main())
