import AppKit
import SwiftUI

@main
struct VigilApp: App {
    @NSApplicationDelegateAdaptor private var delegate: AppDelegate

    init() {
        // `Vigil --report` prints the report to the terminal instead of opening a window.
        if CommandLine.arguments.contains("--report") {
            print(Report.markdown(Checks.all(), date: .now))
            exit(0)
        }
    }

    var body: some Scene {
        Window("Vigil", id: "main") {
            ContentView()
        }
        .defaultSize(width: 560, height: 760)
        .windowToolbarStyle(.unifiedCompact)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@MainActor
final class Scan: ObservableObject {
    @Published var groups: [CheckGroup] = []
    @Published var running = false
    @Published var date: Date?

    var checks: [Check] { groups.flatMap(\.checks) }
    var warnings: Int { checks.filter { $0.status == .warn }.count }
    /// Checks with a clear right answer; informational ones are left out of the score.
    var scored: Int { checks.filter { $0.status != .info }.count }

    func run() {
        guard !running else { return }
        running = true
        Task {
            // Checking can finish in a blink; keep the spinner up long enough to show that it ran.
            async let minimum: Void = (try? await Task.sleep(for: .milliseconds(700))) ?? ()
            let result = await Task.detached { Checks.all() }.value
            await minimum
            groups = result
            date = .now
            running = false
        }
    }
}

enum Report {
    static func markdown(_ groups: [CheckGroup], date: Date) -> String {
        var lines = ["# Vigil report", "", "\(Host.current().localizedName ?? "Mac") · \(date.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(Checks.english)))"]
        for group in groups {
            lines += ["", "## \(group.title)"]
            for check in group.checks {
                let mark = switch check.status { case .pass: "✅"; case .warn: "⚠️"; case .info: "ℹ️" }
                lines.append("- \(mark) **\(check.title)**: \(check.detail)")
                for item in check.items { lines.append("  - \(item.name) (\(item.detail))") }
            }
        }
        return lines.joined(separator: "\n")
    }
}

struct ContentView: View {
    @StateObject private var scan = Scan()
    @State private var copied = false

    var body: some View {
        Form {
            Section { header }
            ForEach(scan.groups) { group in
                Section(group.title) {
                    ForEach(group.checks) { CheckRow(check: $0) }
                }
            }
            if !scan.groups.isEmpty {
                Section {
                    VStack(spacing: 6) {
                        Text("Vigil only reads. It never changes a setting, sends data anywhere or runs anything as administrator.")
                        HStack(spacing: 4) {
                            Text("© 2026 Dominik Rudkowski ·")
                            Link("Source code", destination: URL(string: "https://github.com/rudkowski-dominik/Vigil")!)
                        }
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .multilineTextAlignment(.center)
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 480, minHeight: 520)
        .onAppear { scan.run() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            // Coming back from System Settings: show the effect of what the user just changed.
            if scan.date != nil { scan.run() }
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 84, height: 84)
                .overlay(alignment: .bottomTrailing) {
                    if let badge = headerBadge {
                        Image(systemName: badge)
                            .font(.system(size: 24))
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, headerColor)
                            .background(Circle().fill(.background).padding(2))
                            .offset(x: 2, y: 2)
                    }
                }
                .padding(.top, 6)

            Text(headline)
                .font(.title2.weight(.semibold))

            Text(subtitle)
                .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Button(action: scan.run) {
                    HStack(spacing: 6) {
                        if scan.running {
                            ProgressView().controlSize(.small)
                        }
                        Text(scan.running ? "Checking…" : "Check Again")
                    }
                    .frame(minWidth: 110)
                }
                .buttonStyle(.borderedProminent)
                .disabled(scan.running)

                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(Report.markdown(scan.groups, date: scan.date ?? .now), forType: .string)
                    withAnimation { copied = true }
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        withAnimation { copied = false }
                    }
                } label: {
                    Label(copied ? "Copied" : "Copy Report", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .frame(minWidth: 110)
                }
                .disabled(scan.groups.isEmpty)
            }
            .controlSize(.large)
            .padding(.vertical, 6)
        }
        .frame(maxWidth: .infinity)
        .multilineTextAlignment(.center)
    }

    /// The app icon carries a badge with the result, like a notification badge on a Dock icon.
    private var headerBadge: String? {
        if scan.groups.isEmpty { return nil }
        return scan.warnings == 0 ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
    }

    private var headerColor: Color {
        scan.warnings == 0 ? .green : .orange
    }

    private var headline: String {
        if scan.groups.isEmpty { return "Checking your Mac…" }
        switch scan.warnings {
        case 0: return "Your Mac is well protected"
        case 1: return "1 thing needs your attention"
        default: return "\(scan.warnings) things need your attention"
        }
    }

    private var subtitle: String {
        guard let date = scan.date else { return "This takes a few seconds." }
        let passed = scan.scored - scan.warnings
        return "\(passed) of \(scan.scored) checks passed · \(date.formatted(Date.FormatStyle(date: .omitted, time: .shortened).locale(Checks.english)))"
    }
}

struct CheckRow: View {
    let check: Check
    @State private var expanded = false

    var body: some View {
        if check.items.isEmpty {
            summary
        } else {
            DisclosureGroup(isExpanded: $expanded) {
                ForEach(check.items) { ItemRow(item: $0) }
            } label: {
                // The whole row opens the list, not only the small arrow.
                summary
                    .contentShape(Rectangle())
                    .onTapGesture { withAnimation { expanded.toggle() } }
            }
        }
    }

    private var summary: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            StatusButton(status: check.status, hasItems: !check.items.isEmpty)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title)
                Text(check.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if check.status != .pass, let pane = check.pane {
                Button(pane == .fullDiskAccess ? "Allow…" : "Open Settings") { pane.open() }
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 2)
    }
}

struct ItemRow: View {
    let item: Item

    var body: some View {
        HStack(spacing: 10) {
            icon.frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name).lineLimit(1)
                Text(item.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 8)
            if item.status == .warn { StatusIcon(status: .warn) }
        }
        .help(item.path ?? item.detail)
        .contextMenu {
            if let path = item.path {
                Button("Show in Finder") { NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "") }
            }
        }
    }

    @ViewBuilder private var icon: some View {
        if let path = item.path, FileManager.default.fileExists(atPath: path) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable()
        } else {
            Image(systemName: "questionmark.app.dashed").font(.title3).foregroundStyle(.tertiary)
        }
    }
}

/// The status icon of a check. Clicking it explains what the status means.
struct StatusButton: View {
    let status: Status
    let hasItems: Bool
    @State private var showing = false

    var body: some View {
        Button { showing.toggle() } label: { StatusIcon(status: status) }
            .buttonStyle(.plain)
            .help(title)
            .popover(isPresented: $showing, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(title).font(.headline)
                    Text(explanation).fixedSize(horizontal: false, vertical: true)
                }
                .padding(14)
                .frame(width: 280, alignment: .leading)
            }
    }

    private var title: String {
        switch status {
        case .pass: "Passed"
        case .warn: "Needs your attention"
        case .info: "For your information"
        }
    }

    private var explanation: String {
        let list = hasItems ? " Click the row to see the list." : ""
        return switch status {
        case .pass: "This setting protects your Mac."
        case .warn: "This could put your Mac or your data at risk. The description says why. Where there is an Open Settings button, it takes you to the place to change it."
        case .info: "There's no single right answer here, so it doesn't count toward the score. Check that you recognize and expect what Vigil found.\(list)"
        }
    }
}

struct StatusIcon: View {
    let status: Status

    var body: some View {
        switch status {
        case .pass: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .warn: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        case .info: Image(systemName: "info.circle.fill").foregroundStyle(.secondary)
        }
    }
}
