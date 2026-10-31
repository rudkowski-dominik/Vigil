import Foundation
import Security

/// Who signed a program, checked with the same Security framework calls Gatekeeper uses.
enum Signer: Equatable {
    case apple
    case developer(String)
    /// Signed, but without a developer certificate, so nobody vouches for it.
    case adHoc
    case unsigned
    /// The signature is broken: the file was changed after it was signed.
    case invalid
    case missing

    var description: String {
        switch self {
        case .apple: "Apple"
        case .developer(let name): name
        case .adHoc: "Not signed by a developer"
        case .unsigned: "Unsigned"
        case .invalid: "Signature is broken"
        case .missing: "Program is missing"
        }
    }

    var status: Status {
        switch self {
        case .apple: .pass
        case .developer: .info
        case .adHoc, .unsigned, .invalid, .missing: .warn
        }
    }
}

enum CodeSignature {
    static func signer(of path: String) -> Signer {
        guard FileManager.default.fileExists(atPath: path) else { return .missing }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode
        else { return .invalid }

        switch SecStaticCodeCheckValidity(code, [], nil) {
        case errSecSuccess: break
        case errSecCSUnsigned: return .unsigned
        default: return .invalid
        }
        if satisfies(code, "anchor apple") { return .apple }

        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = info as? [String: Any] ?? [:]
        guard let certificate = (dict[kSecCodeInfoCertificates as String] as? [SecCertificate])?.first else { return .adHoc }
        return .developer(developerName(certificate) ?? dict[kSecCodeInfoTeamIdentifier as String] as? String ?? "Unknown developer")
    }

    private static func satisfies(_ code: SecStaticCode, _ requirement: String) -> Bool {
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess else { return false }
        return SecStaticCodeCheckValidity(code, [], compiled) == errSecSuccess
    }

    /// "Developer ID Application: Google LLC (EQHXZ8M8AV)" becomes "Google LLC".
    private static func developerName(_ certificate: SecCertificate) -> String? {
        guard var name = SecCertificateCopySubjectSummary(certificate) as String? else { return nil }
        if let colon = name.firstIndex(of: ":") { name = String(name[name.index(after: colon)...]) }
        if let paren = name.lastIndex(of: "(") { name = String(name[..<paren]) }
        return name.trimmingCharacters(in: .whitespaces)
    }
}
