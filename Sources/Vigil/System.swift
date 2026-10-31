import Foundation

/// Small read-only helpers for asking macOS about its state.
enum System {
    struct Result {
        let output: String
        let status: Int32
    }

    /// Runs a command without privileges and returns its combined output. Gives up after `timeout` seconds.
    static func run(_ path: String, _ arguments: [String] = [], timeout: TimeInterval = 10) -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return Result(output: "", status: -1) }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            if process.isRunning { process.terminate() }
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Result(output: String(decoding: data, as: UTF8.self), status: process.terminationStatus)
    }

    /// Reads a preference file directly, so values set by the system or an administrator are seen as they are.
    static func preferences(_ path: String) -> [String: Any] {
        NSDictionary(contentsOfFile: path) as? [String: Any] ?? [:]
    }

    /// Whether a system launchd service is loaded, which is how sharing services are switched on.
    static func isServiceLoaded(_ label: String) -> Bool {
        run("/bin/launchctl", ["print", "system/\(label)"]).status == 0
    }

    /// Full path of a running process.
    static func path(ofProcess pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }
}
