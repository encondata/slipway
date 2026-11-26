"""Fake commands written in Python, for tests that put them on a PATH.

A ``#!`` line can't hold an interpreter path with a space in it (a checkout under "HSL Suite", say): the
kernel splits it there and reports "bad interpreter". So these scripts start as sh and re-run themselves
with this test run's own Python, quoted.
"""

import shlex
import sys


def python_header() -> str:
    """The first two lines of a fake command written in Python.

    To sh, line 2 is ``exec /usr/bin/env -u PWD -u SHLVL <python> "$0" "$@"``: the two variables sh adds
    (and bash sets again on exec) are dropped, so the fake sees exactly the environment its caller passed
    (the Terraform tests check that). env is named by its full path because some tests give the fakes a
    PATH without it. To Python the line is a harmless string statement, so the rest of the file runs as
    usual with ``sys.argv[0]`` the script's own path.
    """
    return f"#!/bin/sh\n''''exec /usr/bin/env -u PWD -u SHLVL {shlex.quote(sys.executable)} \"$0\" \"$@\" # '''\n"
