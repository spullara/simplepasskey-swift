import Foundation

public enum SimplePasskeyError: Error, Equatable, LocalizedError {
    case invalidBaseURL
    case invalidBase64URL(String)
    case invalidJWT
    case notAuthenticated
    case missingRefreshToken
    case passkeyCeremonyUnavailable
    case unexpectedCredential
    case requestFailed(statusCode: Int, message: String?)
    case keychainFailure(status: Int32)

    public var errorDescription: String? {
        switch self {
        case .invalidBaseURL:
            return "Invalid base URL."
        case .invalidBase64URL:
            return "Invalid base64url value."
        case .invalidJWT:
            return "Invalid JWT."
        case .notAuthenticated:
            return "No authenticated session is available."
        case .missingRefreshToken:
            return "No refresh token is available."
        case .passkeyCeremonyUnavailable:
            return "Passkey authorization is unavailable."
        case .unexpectedCredential:
            return "The authorization ceremony returned an unexpected credential."
        case .requestFailed(let statusCode, let message):
            return message ?? "Request failed with status code \(statusCode)."
        case .keychainFailure(let status):
            return "Keychain operation failed with status \(status)."
        }
    }
}