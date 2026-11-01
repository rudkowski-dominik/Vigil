# Changelog

## 1.1

- **What Could Leak**: a new group of checks for data and traffic that could slip out of your Mac.
  - SSH keys without a passphrase.
  - Passwords and access tokens in shell history and config files. Vigil shows the file and the kind of secret, never the secret itself.
  - Root certificates added besides Apple's, which can be used to read encrypted traffic.
  - A proxy that all traffic goes through, and DNS servers set by hand.
  - A computer name that includes your name, which everyone on the same Wi-Fi sees.
  - Time Machine backups that aren't encrypted.
- App icon, also shown at the top of the window with a badge for the result.

## 1.0

- First release: Protection, Sign-In, Sharing, Who Has Access and Runs Automatically checks.
