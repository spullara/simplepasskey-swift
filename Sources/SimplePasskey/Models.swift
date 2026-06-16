import Foundation

public struct AuthResult: Codable, Equatable {
    public let jwt: String
    public let userId: String
    public let refreshToken: String?
    public let expiresIn: Int?

    public init(jwt: String, userId: String, refreshToken: String? = nil, expiresIn: Int? = nil) {
        self.jwt = jwt
        self.userId = userId
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
    }
}

public struct Session: Codable, Equatable {
    public let jwt: String
    public let userId: String?
    public let refreshToken: String?
    public let expiresAt: Date?

    public var isExpired: Bool {
        isExpiredOrNearExpiry(leeway: 0)
    }

    public func isExpiredOrNearExpiry(leeway: TimeInterval = 60, now: Date = Date()) -> Bool {
        guard let expiresAt else { return true }
        return expiresAt.timeIntervalSince(now) <= leeway
    }
}

public struct StoredTokens: Codable, Equatable {
    public let jwt: String
    public let userId: String?
    public let refreshToken: String?

    public init(jwt: String, userId: String?, refreshToken: String?) {
        self.jwt = jwt
        self.userId = userId
        self.refreshToken = refreshToken
    }
}

struct AuthResultPayload: Codable {
    let jwt: String
    let userId: String?
    let refreshToken: String?
    let expiresIn: Int?
}

struct RefreshRequest: Encodable {
    let refreshToken: String?
}

struct ClientIdRequest: Encodable {
    let clientId: String
}

struct RegistrationOptionsRequest: Encodable {
    let clientId: String
    let displayName: String?
}

struct OptionsEnvelope<Options: Codable & Equatable>: Codable, Equatable {
    let token: String
    let options: Options
    let userId: String?
}

struct VerifyRequest<Credential: Encodable>: Encodable {
    let token: String
    let credential: Credential
}

struct APIErrorPayload: Decodable {
    let error: String?
    let message: String?
}

public struct PublicKeyCredentialCreationOptions: Codable, Equatable {
    public let challenge: String
    public let rp: RelyingParty
    public let user: CredentialUser
    public let pubKeyCredParams: [PublicKeyCredentialParameter]?
    public let timeout: Int?
    public let attestation: String?
    public let excludeCredentials: [PublicKeyCredentialDescriptor]?
    public let authenticatorSelection: AuthenticatorSelection?

    public init(
        challenge: String,
        rp: RelyingParty,
        user: CredentialUser,
        pubKeyCredParams: [PublicKeyCredentialParameter]? = nil,
        timeout: Int? = nil,
        attestation: String? = nil,
        excludeCredentials: [PublicKeyCredentialDescriptor]? = nil,
        authenticatorSelection: AuthenticatorSelection? = nil
    ) {
        self.challenge = challenge
        self.rp = rp
        self.user = user
        self.pubKeyCredParams = pubKeyCredParams
        self.timeout = timeout
        self.attestation = attestation
        self.excludeCredentials = excludeCredentials
        self.authenticatorSelection = authenticatorSelection
    }
}

public struct PublicKeyCredentialRequestOptions: Codable, Equatable {
    public let challenge: String
    public let rpId: String
    public let timeout: Int?
    public let allowCredentials: [PublicKeyCredentialDescriptor]?
    public let userVerification: String?

    public init(
        challenge: String,
        rpId: String,
        timeout: Int? = nil,
        allowCredentials: [PublicKeyCredentialDescriptor]? = nil,
        userVerification: String? = nil
    ) {
        self.challenge = challenge
        self.rpId = rpId
        self.timeout = timeout
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
    }
}

public struct RelyingParty: Codable, Equatable {
    public let name: String
    public let id: String
}

public struct CredentialUser: Codable, Equatable {
    public let id: String
    public let name: String
    public let displayName: String
}

public struct PublicKeyCredentialParameter: Codable, Equatable {
    public let alg: Int
    public let type: String
}

public struct PublicKeyCredentialDescriptor: Codable, Equatable {
    public let id: String
    public let type: String
    public let transports: [String]?
}

public struct AuthenticatorSelection: Codable, Equatable {
    public let residentKey: String?
    public let userVerification: String?
}