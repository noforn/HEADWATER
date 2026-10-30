# HEADWATER

HEADWATER is a Cisco device access, account collection, and privilege escalation capability. It contains `getUsers`, `getShell`, and `ciscOops.sh` (**[REDACTED]**).

## OBJECTIVE(s):

- Collect local user accounts, roles, and stored password hashes from target devices.
- Obtain command execution or interactive shell access on selected devices.
- Elevate a device foothold from `www-data` to root and execute an operator-supplied command.
- Place files on target devices as required for follow-on operations.
- Establish key-based root SSH access and a reverse tunnel for remote access.
- Remove the SSH access path, terminate the tunnel, and clear related on-device artifacts after operations.
