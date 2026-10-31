import AppKit

enum Status: Comparable {
    case pass, info, warn
}

/// One thing inside a check, such as an app with camera access or a launch agent.
struct Item: Identifiable {
    let name: String
    let detail: String
    /// File or app bundle shown with its Finder icon.
    var path: String?
    var status: Status = .info

    var id: String { (path ?? name) + detail }
}

/// Identified by title, so expanded rows stay expanded when Vigil checks again.
struct Check: Identifiable {
    let title: String
    let detail: String
    let status: Status
    var pane: SettingsPane?
    var items: [Item] = []

    var id: String { title }
}

struct CheckGroup: Identifiable {
    let title: String
    let checks: [Check]

    var id: String { title }
}

/// System Settings panes a check can send the user to. Vigil itself never changes a setting.
enum SettingsPane: String {
    case privacy = "com.apple.settings.PrivacySecurity.extension"
    case fullDiskAccess = "com.apple.preference.security?Privacy_AllFiles"
    case firewall = "com.apple.Network-Settings.extension?Firewall"
    case softwareUpdate = "com.apple.Software-Update-Settings.extension"
    case lockScreen = "com.apple.Lock-Screen-Settings.extension"
    case users = "com.apple.Users-Groups-Settings.extension"
    case sharing = "com.apple.Sharing-Settings.extension"
    case airDrop = "com.apple.AirDrop-Handoff-Settings.extension"
    case loginItems = "com.apple.LoginItems-Settings.extension"

    func open() {
        if let url = URL(string: "x-apple.systempreferences:\(rawValue)") {
            NSWorkspace.shared.open(url)
        }
    }
}
