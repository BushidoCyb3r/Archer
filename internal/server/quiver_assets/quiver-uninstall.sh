#!/bin/sh
# /usr/local/bin/quiver-uninstall.sh — sensor self-clean.
#
# Two callers:
#   1. The admin runs `sudo /usr/local/bin/quiver-uninstall.sh` directly.
#   2. quiver.sh invokes it via sudo when the next /api/quiver/checkin
#      response says the sensor has been disenrolled — at which point
#      the sensor cleans up after itself without any operator action.
#
# Tightly scoped to what /etc/sudoers.d/quiver allows the quiver user
# to run via sudo: this script and nothing else. Removes the install
# footprint placed by install.sh — cron entry, push script, sudoers
# fragment, /etc/quiver/ (config + ssh key + known_hosts) — then
# self-deletes.
#
# What this does NOT touch:
#   - The 'quiver' system user (left in place; harmless once cron and
#     scripts are gone, and userdel can fail if any process is still
#     attached to the uid).
#   - /var/lib/quiver/  (the user's home — flock file lives here; if
#     you also want the user removed, do `sudo userdel -r quiver`
#     after this script finishes).
#   - Logs already pushed to Archer. This is a sensor-side uninstall
#     only; everything in /logs/<sensor-name>/ on the server is
#     independent. The Archer admin can purge that tree separately
#     via the Sensors modal.
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
