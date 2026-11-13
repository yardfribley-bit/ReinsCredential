#!/usr/bin/env python3
"""Keep this interpreter in the child chain.

The caller is Xcode's Python.app. This process waits on the next command
instead of exec, so the desktop-agent walk still sees the toolchain hop.
"""
import subprocess
import sys

if len(sys.argv) < 2:
    raise SystemExit(2)
raise SystemExit(subprocess.call(sys.argv[1:]))
