import AppKit
import SQLite3

/// Reads which apps you allowed to use the camera, microphone, screen and other protected resources.
/// macOS keeps these decisions in two TCC databases that only apps with Full Disk Access can read.
enum Privacy {
    static let services: [(key: String, title: String, noun: String)] = [
        ("kTCCServiceSystemPolicyAllFiles", "Full Disk Access", "can read all your files"),
        ("kTCCServiceScreenCapture", "Screen Recording", "can record your screen"),
        ("kTCCServiceAccessibility", "Accessibility", "can control your Mac"),
        ("kTCCServiceListenEvent", "Input Monitoring", "can see what you type"),
        ("kTCCServiceCamera", "Camera", "can use your camera"),
        ("kTCCServiceMicrophone", "Microphone", "can use your microphone"),
    ]

    static let databases = [
        "/Library/Application Support/com.apple.TCC/TCC.db",
        NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
    ]

    static func checks() -> [Check] {
        guard let grants = readGrants() else {
            return [Check(
                title: "App Permissions",
                detail: "To see which apps can use your camera, microphone and screen, give Vigil Full Disk Access. It only reads.",
                status: .info, pane: .fullDiskAccess
            )]
        }
        return services.map { service in
            let items = (grants[service.key] ?? [])
                .map(item(for:))
                .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            return Check(
                title: service.title,
                detail: items.isEmpty ? "No apps \(service.noun)."
                    : "\(items.count) \(items.count == 1 ? "app" : "apps") \(service.noun). Remove any you don't use.",
                status: items.isEmpty ? .pass : .info, pane: .privacy, items: items
            )
        }
    }

    /// Allowed clients per service, or nil when the databases can't be read (no Full Disk Access).
    static func readGrants() -> [String: Set<String>]? {
        var grants: [String: Set<String>] = [:]
        var readAny = false
        for path in databases {
            var db: OpaquePointer?
            defer { sqlite3_close(db) }
            // The paths contain spaces, which a SQLite URI needs percent-encoded.
            guard let encoded = path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed),
                  sqlite3_open_v2("file:\(encoded)?mode=ro", &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK
            else { continue }
            var statement: OpaquePointer?
            defer { sqlite3_finalize(statement) }
            // auth_value 2 is "allowed", 3 is "limited" (for example a single window).
            let sql = "SELECT service, client FROM access WHERE auth_value >= 2"
            guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { continue }
            readAny = true
            while sqlite3_step(statement) == SQLITE_ROW {
                guard let service = sqlite3_column_text(statement, 0), let client = sqlite3_column_text(statement, 1) else { continue }
                grants[String(cString: service), default: []].insert(String(cString: client))
            }
        }
        return readAny ? grants : nil
    }

    /// A client is a bundle identifier, or a path for command-line tools.
    private static func item(for client: String) -> Item {
        if client.hasPrefix("/") {
            let exists = FileManager.default.fileExists(atPath: client)
            return Item(name: (client as NSString).lastPathComponent,
                        detail: exists ? client : "\(client) · no longer installed", path: exists ? client : nil)
        }
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: client) {
            return Item(name: FileManager.default.displayName(atPath: url.path).replacingOccurrences(of: ".app", with: ""),
                        detail: client, path: url.path)
        }
        return Item(name: client, detail: "App no longer installed")
    }
}
