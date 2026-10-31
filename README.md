# Vigil

**A security checkup for your Mac. One window, about two seconds, and it never changes anything.**

Vigil checks the settings that matter most for keeping a Mac safe. It also shows which apps can use your camera, microphone and screen, and which programs start on their own. For anything that needs attention, a button opens the right place in System Settings.

It is open source so you can see exactly what it reads. It never writes, never asks for an administrator password and never sends data anywhere.

## What it checks

| Group | Check | Passes when |
|---|---|---|
| Protection | FileVault | The startup disk is encrypted |
| | Firewall | The application firewall is on |
| | System Integrity Protection | SIP is enabled |
| | Gatekeeper | App assessments are enabled |
| | Security Updates | Automatic checks, security responses and system data files are not turned off |
| | XProtect | Apple's malware definitions were updated in the last 60 days |
| Sign-In | Screen Lock | A password is required within 5 minutes of sleep or the screen saver |
| | Automatic Login | Off |
| | Guest User | Off |
| Sharing | Remote Login, Screen Sharing, File Sharing, Remote Apple Events | Off |
| | AirDrop | Not visible to everyone |
| | Apps Accepting Connections | Lists apps that listen on a network address, with who signed them |
| Who Has Access | Full Disk Access, Screen Recording, Accessibility, Input Monitoring, Camera, Microphone | Lists the apps you allowed |
| Runs Automatically | Launch Agents and Daemons | Every background program is signed by an identified developer |
| | System Extensions | Lists installed extensions |
| | Device Management | Shows whether an organization manages the Mac |

Items marked with ⓘ have no single right answer. Vigil shows them so you can decide, and they don't count toward the score.

## Requirements

- macOS 14 Sonoma or later
- Apple Silicon or Intel

## Install

1. Download `Vigil.zip` from [Releases](../../releases) and move `Vigil.app` to Applications.
2. The app isn't notarized yet, so the first time **right-click it → Open → Open**.
3. Optional: to see which apps have access to your camera, microphone and screen, add Vigil under
   **System Settings → Privacy & Security → Full Disk Access**. macOS keeps those permissions in a database
   that only apps with Full Disk Access can read. Vigil opens it read-only.

Vigil checks again each time you come back to it, so after you change something in System Settings you see the result right away.

## How it works

Every check uses a public macOS command or reads a file. Nothing runs as root. You can run each one yourself:

| Check | Source |
|---|---|
| FileVault | `fdesetup status` |
| Firewall | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` and `--getstealthmode` |
| System Integrity Protection | `csrutil status` |
| Gatekeeper | `spctl --status` |
| Security Updates | `/Library/Preferences/com.apple.SoftwareUpdate.plist` |
| XProtect | Version and date of `/Library/Apple/System/Library/CoreServices/XProtect.bundle` |
| Screen Lock | `sysadminctl -screenLock status` |
| Automatic Login, Guest User | `/Library/Preferences/com.apple.loginwindow.plist` |
| Sharing services | `launchctl print system/<service>` for `com.openssh.sshd`, `com.apple.screensharing`, `com.apple.smbd`, `com.apple.AEServer` |
| AirDrop | `DiscoverableMode` in `com.apple.sharingd` preferences |
| Apps Accepting Connections | `lsof -iTCP -sTCP:LISTEN`, without loopback addresses |
| Who Has Access | The TCC databases in `/Library/Application Support/com.apple.TCC/` and `~/Library/Application Support/com.apple.TCC/`, opened read-only |
| Launch Agents and Daemons | Property lists in `~/Library/LaunchAgents`, `/Library/LaunchAgents` and `/Library/LaunchDaemons` |
| System Extensions | `systemextensionsctl list` |
| Device Management | `profiles status -type enrollment` |

Code signatures are verified with the Security framework (`SecStaticCodeCheckValidity`), the same API Gatekeeper uses. A program counts as signed when it carries a valid Apple or Developer ID signature. Ad-hoc signatures and broken signatures are flagged, because nobody vouches for that code.

To print the report in Terminal instead of opening the window:

```sh
/Applications/Vigil.app/Contents/MacOS/Vigil --report
```

### Limits

- **Apps Accepting Connections** sees only processes that run as you. System services are covered by the Sharing checks.
- **Login items** that apps register through `SMAppService` are stored in a database that only root can read.
  Vigil lists the launch agents and daemons it can read; System Settings → General → Login Items shows the rest.
- Vigil reports settings. It isn't an antivirus and doesn't scan files for malware. XProtect, built into macOS, does that.

## Build

```sh
./build.sh
```

Produces a universal (Apple Silicon and Intel) `build/Vigil.app` and `build/Vigil.zip`.
Needs Xcode command line tools. No dependencies.

## License

MIT
