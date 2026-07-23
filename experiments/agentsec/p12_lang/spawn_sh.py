#!/usr/bin/python3
# P12 target (Python): after launch, attempt to spawn a shell via a second execve.
import os
os.execv("/bin/sh", ["sh", "-c", "echo LANG_PY_PWNED"])
