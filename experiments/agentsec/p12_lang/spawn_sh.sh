#!/bin/sh
# P12 target (shell): after launch, replace image with a shell via a second execve.
exec /bin/sh -c "echo LANG_SH_PWNED"
