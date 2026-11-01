import Foundation

/// Every check Vigil runs. Each one only reads; none needs an administrator password.
enum Checks {
    /// The interface is in English, so dates and durations are too, whatever the system language.
    static let english = Locale(identifier: "en_US")

    static func all() -> [CheckGroup] {
        [
            CheckGroup(title: "Protection", checks: [fileVault(), firewall(), systemIntegrity(), gatekeeper(), updates(), xProtect()]),
            CheckGroup(title: "Sign-In", checks: [screenLock(), automaticLogin(), guestAccount()]),
            CheckGroup(title: "Sharing", checks: sharingServices() + [airDrop(), networkListeners()]),
            CheckGroup(title: "Who Has Access", checks: Privacy.checks()),
            CheckGroup(title: "What Could Leak", checks: Leaks.checks()),
            CheckGroup(title: "Runs Automatically", checks: [launchItems(), systemExtensions(), management()]),
        ]
    }

    // MARK: Protection

    static func fileVault() -> Check {
        let on = System.run("/usr/bin/fdesetup", ["status"]).output.contains("FileVault is On")
        return Check(
            title: "FileVault",
            detail: on ? "Your disk is encrypted. Nobody can read it without your password."
                       : "Your disk isn't encrypted. Anyone holding your Mac can read your files.",
            status: on ? .pass : .warn, pane: .privacy
        )
    }

    static func firewall() -> Check {
        let tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        // State 1 is on, 2 blocks all incoming connections. If the state can't be read, don't report a pass.
        let state = System.run(tool, ["--getglobalstate"]).output.firstMatch(of: #/State = (\d)/#).flatMap { Int($0.1) }
        let on = (state ?? 0) > 0
        let stealth = System.run(tool, ["--getstealthmode"]).output.contains(" on")
        return Check(
            title: "Firewall",
            detail: on ? "Blocks unwanted incoming connections\(stealth ? ", and your Mac doesn't answer probes" : "")."
                       : "Off. Apps can accept connections from any device on your network.",
            status: on ? .pass : .warn, pane: .firewall
        )
    }

    static func systemIntegrity() -> Check {
        let on = System.run("/usr/bin/csrutil", ["status"]).output.contains("status: enabled")
        return Check(
            title: "System Integrity Protection",
            detail: on ? "macOS system files can't be modified, even by an administrator."
                       : "Off. Malware with your password could change macOS itself. Turn it on from Recovery.",
            status: on ? .pass : .warn
        )
    }

    static func gatekeeper() -> Check {
        let on = System.run("/usr/sbin/spctl", ["--status"]).output.contains("assessments enabled")
        return Check(
            title: "Gatekeeper",
            detail: on ? "Apps are checked for known malware and a valid signature before they open."
                       : "Off. Any app opens without being checked.",
            status: on ? .pass : .warn, pane: .privacy
        )
    }

    static func updates() -> Check {
        let prefs = System.preferences("/Library/Preferences/com.apple.SoftwareUpdate.plist")
        // A missing key means the macOS default, which is on.
        let off = ["AutomaticCheckEnabled", "CriticalUpdateInstall", "ConfigDataInstall"]
            .filter { (prefs[$0] as? Bool) == false }
        return Check(
            title: "Security Updates",
            detail: off.isEmpty ? "Security responses and system data files install automatically."
                                : "Automatic security updates are off. Fixes for attacks arrive late or not at all.",
            status: off.isEmpty ? .pass : .warn, pane: .softwareUpdate
        )
    }

    static func xProtect() -> Check {
        let path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        let version = System.preferences(path)["CFBundleShortVersionString"] as? String
        let modified = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        guard let version, let modified else {
            return Check(title: "XProtect", detail: "Couldn't find Apple's built-in malware definitions.", status: .warn, pane: .softwareUpdate)
        }
        let days = Calendar.current.dateComponents([.day], from: modified, to: .now).day ?? 0
        let when = modified.formatted(.relative(presentation: .named).locale(english))
        return Check(
            title: "XProtect",
            detail: days > 60 ? "Malware definitions are out of date (version \(version), updated \(when))."
                              : "Malware definitions are current (version \(version), updated \(when)).",
            status: days > 60 ? .warn : .pass, pane: .softwareUpdate
        )
    }

    // MARK: Sign-In

    static func screenLock() -> Check {
        let output = System.run("/usr/sbin/sysadminctl", ["-screenLock", "status"]).output
        let seconds: Int? = if output.contains("immediate") { 0 }
            else if let match = output.firstMatch(of: #/delay is (\d+) seconds/#) { Int(match.1) }
            else { nil }
        guard let seconds else {
            return Check(title: "Screen Lock", detail: "Your Mac doesn't ask for a password after sleep or the screen saver.", status: .warn, pane: .lockScreen)
        }
        let delay = seconds == 0 ? "immediately" : "after " + Duration.seconds(seconds).formatted(.units(allowed: [.hours, .minutes, .seconds], width: .wide).locale(english))
        return Check(
            title: "Screen Lock",
            detail: seconds <= 300 ? "Asks for your password \(delay) after sleep or the screen saver."
                                   : "Asks for your password only \(delay). Anyone nearby can use your Mac until then.",
            status: seconds <= 300 ? .pass : .warn, pane: .lockScreen
        )
    }

    static func automaticLogin() -> Check {
        let user = System.preferences("/Library/Preferences/com.apple.loginwindow.plist")["autoLoginUser"] as? String
        return Check(
            title: "Automatic Login",
            detail: user == nil ? "Off. Your Mac asks for a password when it starts."
                                : "On for \(user!). Anyone who restarts your Mac gets into your account.",
            status: user == nil ? .pass : .warn, pane: .users
        )
    }

    static func guestAccount() -> Check {
        let on = System.preferences("/Library/Preferences/com.apple.loginwindow.plist")["GuestEnabled"] as? Bool ?? false
        return Check(
            title: "Guest User",
            detail: on ? "On. Anyone can log in without a password." : "Off.",
            status: on ? .warn : .pass, pane: .users
        )
    }

    // MARK: Sharing

    static func sharingServices() -> [Check] {
        let services = [
            ("Remote Login (SSH)", "com.openssh.sshd", "Anyone on your network who knows a user's password can run commands."),
            ("Screen Sharing", "com.apple.screensharing", "Anyone on your network who knows a user's password can see and control this Mac."),
            ("File Sharing", "com.apple.smbd", "Shared folders can be opened from other devices on your network."),
            ("Remote Apple Events", "com.apple.AEServer", "Apps on other Macs can send commands to apps on this one."),
        ]
        return services.map { title, label, risk in
            let on = System.isServiceLoaded(label)
            return Check(title: title, detail: on ? "On. \(risk)" : "Off.", status: on ? .warn : .pass, pane: .sharing)
        }
    }

    static func airDrop() -> Check {
        let mode = CFPreferencesCopyAppValue("DiscoverableMode" as CFString, "com.apple.sharingd" as CFString) as? String
        let everyone = mode == "Everyone"
        return Check(
            title: "AirDrop",
            detail: everyone ? "Visible to everyone nearby. Strangers can send you files."
                             : mode == "Off" ? "Off." : "Visible to your contacts only.",
            status: everyone ? .warn : .pass, pane: .airDrop
        )
    }

    /// Apps listening for connections on a network address, not just on this Mac (127.0.0.1).
    /// lsof only sees processes that run as you, so system services are covered by the sharing checks above.
    static func networkListeners() -> Check {
        let output = System.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-FpcnT"]).output
        var ports: [Int32: (command: String, ports: Set<String>)] = [:]
        var pid: Int32 = 0, command = ""
        for line in output.split(separator: "\n") {
            let value = String(line.dropFirst())
            switch line.first {
            case "p": pid = Int32(value) ?? 0
            case "c": command = value
            case "n":
                guard !value.hasPrefix("127.") && !value.hasPrefix("[::1]") && !value.hasPrefix("localhost") else { continue }
                let port = String(value.split(separator: ":").last ?? "")
                ports[pid, default: (command, [])].ports.insert(port)
            default: break
            }
        }

        var byPath: [String: (name: String, ports: Set<String>)] = [:]
        for (pid, entry) in ports {
            // lsof cuts command names to 9 characters, so prefer the app or file name from the full path.
            let path = System.path(ofProcess: pid) ?? entry.command
            let name = appName(forExecutable: path) ?? (path.hasPrefix("/") ? (path as NSString).lastPathComponent : entry.command)
            byPath[path, default: (name, [])].ports.formUnion(entry.ports)
        }
        let items = byPath.map { path, entry in
            let signer = CodeSignature.signer(of: path)
            let portList = entry.ports.sorted { (Int($0) ?? 0) < (Int($1) ?? 0) }.joined(separator: ", ")
            return Item(name: entry.name, detail: "\(signer.description) · port \(portList)", path: bundlePath(forExecutable: path) ?? path,
                        status: signer == .apple ? .pass : .info)
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }

        let others = items.filter { $0.status != .pass }
        return Check(
            title: "Apps Accepting Connections",
            detail: others.isEmpty ? "Only macOS accepts connections from other devices."
                : "\(others.count) \(others.count == 1 ? "app accepts" : "apps accept") connections from other devices on your network. Make sure you expect this.",
            status: others.isEmpty ? .pass : .info, pane: .firewall, items: items
        )
    }

    // MARK: Runs Automatically

    static func launchItems() -> Check {
        let folders = [
            NSHomeDirectory() + "/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]
        var items: [Item] = []
        for folder in folders {
            let files = (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []
            for file in files where file.hasSuffix(".plist") {
                let plist = System.preferences("\(folder)/\(file)")
                if plist["Disabled"] as? Bool == true { continue }
                let label = plist["Label"] as? String ?? String(file.dropLast(6))
                let program = plist["Program"] as? String ?? (plist["ProgramArguments"] as? [String])?.first
                guard let program else {
                    // BundleProgram items live inside an app and are listed under Login Items in System Settings.
                    items.append(Item(name: label, detail: "Runs a program inside an app", path: nil, status: .info))
                    continue
                }
                let signer = CodeSignature.signer(of: program)
                let kind = folder.hasSuffix("Daemons") ? "Runs as root" : "Runs when you log in"
                items.append(Item(name: label, detail: "\(signer.description) · \(kind)",
                                  path: bundlePath(forExecutable: program) ?? program, status: signer.status == .pass ? .info : signer.status))
            }
        }
        items.sort { ($0.status, $1.name) > ($1.status, $0.name) }
        let flagged = items.filter { $0.status == .warn }
        return Check(
            title: "Launch Agents and Daemons",
            detail: items.isEmpty ? "No third-party programs start automatically."
                : flagged.isEmpty ? "\(items.count) background \(items.count == 1 ? "program starts" : "programs start") automatically. All are signed by a known developer."
                : "\(flagged.count) of \(items.count) background programs aren't signed by a known developer. Check that you recognize them.",
            status: items.isEmpty ? .pass : flagged.isEmpty ? .info : .warn, pane: .loginItems, items: items
        )
    }

    static func systemExtensions() -> Check {
        let output = System.run("/usr/bin/systemextensionsctl", ["list"]).output
        let items = output.split(separator: "\n").compactMap { line -> Item? in
            // Empty columns matter: an extension that isn't enabled has a blank first column.
            let columns = line.split(separator: "\t", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
            guard columns.count >= 6, columns[5].contains("enabled") else { return nil }
            return Item(name: columns[4], detail: "\(columns[3]) · team \(columns[2])")
        }
        return Check(
            title: "System Extensions",
            detail: items.isEmpty ? "None installed."
                : "\(items.count) \(items.count == 1 ? "extension runs" : "extensions run") with deep access to the system, for example network filters or drivers.",
            status: items.isEmpty ? .pass : .info, pane: .loginItems, items: items
        )
    }

    static func management() -> Check {
        let managed = System.run("/usr/bin/profiles", ["status", "-type", "enrollment"]).output.contains("MDM enrollment: Yes")
        return Check(
            title: "Device Management",
            detail: managed ? "This Mac is managed by an organization, which can install apps and change settings."
                            : "This Mac isn't managed by an organization.",
            status: managed ? .info : .pass
        )
    }

    // MARK: Helpers

    /// The .app that contains an executable, if any.
    static func bundlePath(forExecutable path: String) -> String? {
        guard let range = path.range(of: ".app/", options: .backwards) else { return nil }
        return String(path[..<range.lowerBound]) + ".app"
    }

    static func appName(forExecutable path: String) -> String? {
        guard let bundle = bundlePath(forExecutable: path) else { return nil }
        return FileManager.default.displayName(atPath: bundle).replacingOccurrences(of: ".app", with: "")
    }
}
