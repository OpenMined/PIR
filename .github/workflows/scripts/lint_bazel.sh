#!/bin/sh
set -e

# Lint files (all BUILD) inplace.
find ./pir/  \( -iname BUILD \) | xargs buildifier
if [ $? -ne 0 ]
then
    exit 1
fi

# Print changes.
git diff
# Already well formated if 'git diff' doesn't output anything.
! ( git diff |  grep -q ^ ) || exit 1
