#!/bin/sh
# /usr/local/bin/quiver-uninstall.sh — invoked via sudo by quiver.sh
# when the sensor learns it has been disenrolled. Tightly scoped to
# what the sudoers fragment allows: removing the install footprint,
# nothing else.
set -eu

rm -f /etc/cron.d/quiver
rm -f /usr/local/bin/quiver.sh
rm -f /etc/sudoers.d/quiver
rm -rf /etc/quiver

# Leave the quiver user in place. userdel can fail on systems that
# don't allow removing a user with running processes, and the user
# is harmless once the cron entry, scripts, and config are gone.

# Self-delete last so the sudoers entry that authorized this call
# is already gone by the time we vanish — defense in depth against
# a stale sudoers reference.
rm -f /usr/local/bin/quiver-uninstall.sh

echo "quiver: uninstalled" >&2
