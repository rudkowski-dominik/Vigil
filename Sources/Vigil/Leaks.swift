import Foundation
import Security
import SystemConfiguration

/// Things on this Mac that could let your data or traffic slip out. Like every other check, these only read.
/// Secrets are never shown: Vigil reports which file holds one and what kind it is, not its value.
enum Leaks {
    static func checks() -> [Check] {
        [sshKeys(), secrets(), trustedCertificates(), proxy(), dns(), computerName(), backups()]
    }

    static let home = NSHomeDirectory()

    // MARK: SSH keys

    static func sshKeys() -> Check {
        let folder = home + "/.ssh"
        let files = (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []
        var items: [Item] = []
        for file in files.sorted() {
            let path = "\(folder)/\(file)"
            // Private keys are small; skipping big files avoids reading anything else that ended up here.
            guard let size = (try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int, size < 64_000,
                  let text = try? String(contentsOfFile: path, encoding: .utf8),
                  let protected = isPassphraseProtected(privateKey: text)
            else { continue }
            items.append(Item(name: file, detail: protected ? "Protected with a passphrase" : "No passphrase",
                              path: path, status: protected ? .pass : .warn))
        }
        let open = items.filter { $0.status == .warn }
        return Check(
            title: "SSH Keys",
            detail: items.isEmpty ? "No private SSH keys found."
                : open.isEmpty ? "Every private key is protected with a passphrase."
                : "\(open.count) private \(open.count == 1 ? "key has" : "keys have") no passphrase. Any app that reads the file can sign in to your servers as you.",
            status: open.isEmpty ? .pass : .warn, items: items
        )
    }

    /// Whether a private key file is encrypted, or nil if the text isn't a private key.
    static func isPassphraseProtected(privateKey text: String) -> Bool? {
        if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") { return true }
        if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            // The OpenSSH format starts with "openssh-key-v1\0", then the length and name of the cipher ("none" if unencrypted).
            let body = text.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
            guard let data = Data(base64Encoded: body), data.count > 19 else { return nil }
            let length = data[15..<19].reduce(0) { $0 << 8 | Int($1) }
            guard data.count >= 19 + length else { return nil }
            return String(decoding: data[19..<(19 + length)], as: UTF8.self) != "none"
        }
        if text.firstMatch(of: #/-----BEGIN [A-Z ]*PRIVATE KEY-----/#) != nil {
            // Older PEM keys mark encryption with a header.
            return text.contains("ENCRYPTED")
        }
        return nil
    }

    // MARK: Tokens and passwords in plain text

    /// Patterns for secrets typed into a shell or saved in a file. Order matters: specific formats come first.
    static let patterns: [(kind: String, regex: Regex<AnyRegexOutput>)] = [
        ("private key", try! Regex(#"-----BEGIN [A-Z ]*PRIVATE KEY-----"#)),
        ("GitHub token", try! Regex(#"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"#)),
        ("AWS key", try! Regex(#"\bAKIA[0-9A-Z]{16}\b"#)),
        ("Anthropic key", try! Regex(#"\bsk-ant-[A-Za-z0-9_-]{20,}"#)),
        ("OpenAI key", try! Regex(#"\bsk-(proj-)?[A-Za-z0-9_-]{32,}"#)),
        ("Stripe key", try! Regex(#"\b[sr]k_live_[0-9A-Za-z]{20,}"#)),
        ("Slack token", try! Regex(#"\bxox[abposr]-[A-Za-z0-9-]{10,}"#)),
        ("Google API key", try! Regex(#"\bAIza[0-9A-Za-z_-]{35}"#)),
        ("password in a URL", try! Regex(#"[a-z]+://[^/\s:@]+:[^/\s@$]{3,}@"#)),
        // Assignments such as `export API_TOKEN=abc123…`. A value starting with $ is a reference, not a secret.
        ("password or token", try! Regex(#"(?i)\b[a-z0-9_]*(token|secret|password|passwd|api_?key)[a-z0-9_]*\s*=\s*["']?[^\s"'$]{8,}"#)),
        ("password or token", try! Regex(#"(?i)--(password|token|api-key)[= ]["']?[^\s"'$-][^\s"']{5,}"#)),
    ]

    /// Configuration files that keep credentials in plain text, with the line that gives one away.
    static let credentialFiles: [(path: String, kind: String, regex: Regex<AnyRegexOutput>)] = [
        ("/.aws/credentials", "AWS secret key", try! Regex(#"aws_secret_access_key\s*="#)),
        ("/.netrc", "password", try! Regex(#"\bpassword\s+\S"#)),
        ("/.git-credentials", "Git password", try! Regex(#"://[^/\s:@]+:[^/\s@]+@"#)),
        ("/.npmrc", "npm token", try! Regex(#"_(authToken|auth|password)\s*="#)),
        ("/.yarnrc.yml", "npm token", try! Regex(#"npmAuthToken\s*:"#)),
        ("/.pypirc", "PyPI password", try! Regex(#"password\s*[=:]"#)),
        ("/.docker/config.json", "Docker password", try! Regex(#""auth"\s*:\s*"[^"]+""#)),
        ("/.config/gh/hosts.yml", "GitHub token", try! Regex(#"oauth_token\s*:"#)),
    ]

    static func secrets() -> Check {
        var items: [Item] = []

        var histories = [home + "/.zsh_history", home + "/.bash_history"]
        let sessions = home + "/.zsh_sessions"
        histories += ((try? FileManager.default.contentsOfDirectory(atPath: sessions)) ?? [])
            .filter { $0.hasSuffix(".history") }.map { "\(sessions)/\($0)" }
        for path in histories {
            guard let data = FileManager.default.contents(atPath: path) else { continue }
            var kinds: [String] = [], lines = 0
            for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
                let found = patterns.filter { line.firstMatch(of: $0.regex) != nil }.map(\.kind)
                guard let first = found.first else { continue }
                lines += 1
                if !kinds.contains(first) { kinds.append(first) }
            }
            if lines > 0 {
                items.append(Item(name: (path as NSString).lastPathComponent,
                                  detail: "\(lines) \(lines == 1 ? "command contains" : "commands contain") \(list(kinds))",
                                  path: path, status: .warn))
            }
        }

        for file in credentialFiles {
            let path = home + file.path
            guard let text = try? String(contentsOfFile: path, encoding: .utf8), text.firstMatch(of: file.regex) != nil else { continue }
            items.append(Item(name: "~" + file.path, detail: "Saved \(file.kind) in plain text", path: path, status: .warn))
        }

        return Check(
            title: "Passwords and Tokens in Plain Text",
            detail: items.isEmpty ? "No passwords or access tokens in your shell history or common config files."
                : "\(items.count) \(items.count == 1 ? "file keeps" : "files keep") passwords or tokens unencrypted. Any app you run can read them. Remove them and use the keychain instead.",
            status: items.isEmpty ? .pass : .warn, items: items
        )
    }

    // MARK: Trusted certificates

    /// Root certificates that you, an app or an administrator added. Apple's own roots aren't listed here.
    static func trustedCertificates() -> Check {
        var items: [Item] = []
        for (domain, whose) in [(SecTrustSettingsDomain.user, "Added for you"), (.admin, "Added for all users")] {
            var certificates: CFArray?
            guard SecTrustSettingsCopyCertificates(domain, &certificates) == errSecSuccess,
                  let certificates = certificates as? [SecCertificate] else { continue }
            for certificate in certificates where isTrustedAsRoot(certificate, in: domain) {
                let name = SecCertificateCopySubjectSummary(certificate) as String? ?? "Unnamed certificate"
                items.append(Item(name: name, detail: whose, status: .warn))
            }
        }
        return Check(
            title: "Trusted Certificates",
            detail: items.isEmpty ? "Only Apple's built-in certificates can vouch for websites."
                : "\(items.count) added \(items.count == 1 ? "certificate can" : "certificates can") vouch for any website. Whoever holds its key can read your encrypted traffic. Remove it in Keychain Access unless you added it, for example for development.",
            status: items.isEmpty ? .pass : .warn, items: items
        )
    }

    /// A certificate with no trust settings, or with "always trust", is trusted as a root. "Never trust" entries are harmless.
    static func isTrustedAsRoot(_ certificate: SecCertificate, in domain: SecTrustSettingsDomain) -> Bool {
        var settings: CFArray?
        guard SecTrustSettingsCopyTrustSettings(certificate, domain, &settings) == errSecSuccess,
              let settings = settings as? [[String: Any]] else { return false }
        if settings.isEmpty { return true }
        return settings.contains { setting in
            let result = (setting[kSecTrustSettingsResult as String] as? NSNumber).flatMap { SecTrustSettingsResult(rawValue: $0.uint32Value) } ?? .trustRoot
            return result == .trustRoot || result == .trustAsRoot
        }
    }

    // MARK: Network

    static func proxy() -> Check {
        let settings = SCDynamicStoreCopyProxies(nil) as? [String: Any] ?? [:]
        var items: [Item] = []
        for (kind, enable, host, port) in [("Web", "HTTPEnable", "HTTPProxy", "HTTPPort"),
                                            ("Secure web", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"),
                                            ("SOCKS", "SOCKSEnable", "SOCKSProxy", "SOCKSPort")]
        where settings[enable] as? Int == 1 {
            let address = (settings[host] as? String ?? "?") + ((settings[port] as? Int).map { ":\($0)" } ?? "")
            items.append(Item(name: address, detail: "\(kind) proxy", status: .warn))
        }
        if settings["ProxyAutoConfigEnable"] as? Int == 1 {
            items.append(Item(name: settings["ProxyAutoConfigURLString"] as? String ?? "Automatic configuration",
                              detail: "Proxy configuration file", status: .warn))
        }
        return Check(
            title: "Proxy",
            detail: items.isEmpty ? "Your traffic goes straight to the internet, not through a proxy."
                : "Your traffic goes through a proxy, which can see and change what isn't encrypted. Malware sets one up quietly. Make sure you or your organization did.",
            status: items.isEmpty ? .pass : .warn, pane: .network, items: items
        )
    }

    static let knownResolvers = [
        "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
        "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    ]

    /// DNS servers typed in by hand rather than handed out by the network. A rogue DNS server can send you to fake websites.
    static func dns() -> Check {
        let store = SCDynamicStoreCreate(nil, "Vigil" as CFString, nil, nil)
        let primary = (SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any])?["PrimaryService"] as? String
        let manual = primary.flatMap {
            (SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\($0)/DNS" as CFString) as? [String: Any])?["ServerAddresses"] as? [String]
        } ?? []
        let items = manual.map { Item(name: $0, detail: knownResolvers[$0].map { "\($0) public DNS" } ?? "Set by hand") }
        let unknown = manual.filter { knownResolvers[$0] == nil }
        return Check(
            title: "DNS Servers",
            detail: manual.isEmpty ? "Uses the DNS servers your network provides."
                : unknown.isEmpty ? "Set by hand to a well-known public DNS service."
                : "Set by hand. Whoever runs a DNS server decides which website a name leads to. Make sure you recognize it.",
            status: manual.isEmpty || unknown.isEmpty ? .pass : .info, pane: .network, items: items
        )
    }

    // MARK: Identity

    /// Other devices on the same network, such as a café's Wi-Fi, see the computer name.
    static func computerName() -> Check {
        let names = [SCDynamicStoreCopyComputerName(nil, nil) as String?, SCDynamicStoreCopyLocalHostName(nil) as String?].compactMap { $0 }
        let words = Set((NSFullUserName().split(separator: " ").map(String.init) + [NSUserName()])
            .filter { $0.count >= 3 })
        let fold: (String) -> String = { $0.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil) }
        let revealed = words.contains { word in names.contains { fold($0).contains(fold(word)) } }
        let name = names.first ?? "Mac"
        return Check(
            title: "Computer Name",
            detail: revealed ? "“\(name)” includes your name. Everyone on the same Wi-Fi network can see it."
                             : "“\(name)” doesn't include your name.",
            status: revealed ? .warn : .pass, pane: .about
        )
    }

    // MARK: Backups

    static func backups() -> Check {
        let destinations = System.preferences("/Library/Preferences/com.apple.TimeMachine.plist")["Destinations"] as? [[String: Any]] ?? []
        guard !destinations.isEmpty else {
            return Check(title: "Time Machine Backups", detail: "Time Machine isn't set up.", status: .info, pane: .timeMachine)
        }
        let states = destinations.map { $0["LastKnownEncryptionState"] as? String }
        let unencrypted = states.filter { $0 == "NotEncrypted" }.count
        let unknown = states.filter { $0 != "Encrypted" && $0 != "NotEncrypted" }.count
        return Check(
            title: "Time Machine Backups",
            detail: unencrypted > 0 ? "\(unencrypted) backup \(unencrypted == 1 ? "disk isn't" : "disks aren't") encrypted. Anyone holding the disk can read a copy of all your files."
                : unknown > 0 ? "Couldn't tell whether every backup is encrypted."
                : "Your backups are encrypted.",
            status: unencrypted > 0 ? .warn : unknown > 0 ? .info : .pass, pane: .timeMachine
        )
    }

    // MARK: Helpers

    static func list(_ words: [String]) -> String {
        let articled = words.map { word in
            let vowel = word.first.map { "aeiouAEIOU".contains($0) } ?? false
            return (vowel ? "an " : "a ") + word
        }
        return articled.count <= 1 ? articled.joined() : articled.dropLast().joined(separator: ", ") + " and " + articled.last!
    }
}
