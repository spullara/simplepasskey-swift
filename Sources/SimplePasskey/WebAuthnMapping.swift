import Foundation

public struct RegistrationRequestParameters: Equatable {
    public let relyingPartyIdentifier: String
    public let challenge: Data
    public let name: String
    public let userID: Data
    public let displayName: String
    public let userVerification: String?
    public let attestation: String?
    public let excludedCredentialIDs: [Data]
}

public struct AssertionRequestParameters: Equatable {
    public let relyingPartyIdentifier: String
    public let challenge: Data
    public let userVerification: String?
    public let allowedCredentialIDs: [Data]
}

public struct PlatformRegistrationCredential: Equatable {
    public let credentialID: Data
    public let rawClientDataJSON: Data
    public let rawAttestationObject: Data

    public init(credentialID: Data, rawClientDataJSON: Data, rawAttestationObject: Data) {
        self.credentialID = credentialID
        self.rawClientDataJSON = rawClientDataJSON
        self.rawAttestationObject = rawAttestationObject
    }
}

public struct PlatformAssertionCredential: Equatable {
    public let credentialID: Data
    public let rawClientDataJSON: Data
    public let rawAuthenticatorData: Data
    public let signature: Data
    public let userID: Data?

    public init(
        credentialID: Data,
        rawClientDataJSON: Data,
        rawAuthenticatorData: Data,
        signature: Data,
        userID: Data?
    ) {
        self.credentialID = credentialID
        self.rawClientDataJSON = rawClientDataJSON
        self.rawAuthenticatorData = rawAuthenticatorData
        self.signature = signature
        self.userID = userID
    }
}

public struct EmptyClientExtensionResults: Codable, Equatable {
    public init() {}
}

public struct RegistrationCredentialJSON: Codable, Equatable {
    public let id: String
    public let rawId: String
    public let response: RegistrationCredentialResponseJSON
    public let type: String
    public let clientExtensionResults: EmptyClientExtensionResults
    public let authenticatorAttachment: String
}

public struct RegistrationCredentialResponseJSON: Codable, Equatable {
    public let clientDataJSON: String
    public let attestationObject: String
}

public struct AuthenticationCredentialJSON: Codable, Equatable {
    public let id: String
    public let rawId: String
    public let response: AuthenticationCredentialResponseJSON
    public let type: String
    public let clientExtensionResults: EmptyClientExtensionResults
    public let authenticatorAttachment: String
}

public struct AuthenticationCredentialResponseJSON: Codable, Equatable {
    public let clientDataJSON: String
    public let authenticatorData: String
    public let signature: String
    public let userHandle: String?
}

public enum WebAuthnMapper {
    public static func registrationRequestParameters(
        from options: PublicKeyCredentialCreationOptions
    ) throws -> RegistrationRequestParameters {
        RegistrationRequestParameters(
            relyingPartyIdentifier: options.rp.id,
            challenge: try Base64URL.decode(options.challenge),
            name: options.user.name,
            userID: try Base64URL.decode(options.user.id),
            displayName: options.user.displayName,
            userVerification: options.authenticatorSelection?.userVerification,
            attestation: options.attestation,
            excludedCredentialIDs: try (options.excludeCredentials ?? []).map { try Base64URL.decode($0.id) }
        )
    }

    public static func assertionRequestParameters(
        from options: PublicKeyCredentialRequestOptions
    ) throws -> AssertionRequestParameters {
        AssertionRequestParameters(
            relyingPartyIdentifier: options.rpId,
            challenge: try Base64URL.decode(options.challenge),
            userVerification: options.userVerification,
            allowedCredentialIDs: try (options.allowCredentials ?? []).map { try Base64URL.decode($0.id) }
        )
    }

    public static func registrationCredentialJSON(
        from credential: PlatformRegistrationCredential
    ) -> RegistrationCredentialJSON {
        let credentialID = Base64URL.encode(credential.credentialID)
        return RegistrationCredentialJSON(
            id: credentialID,
            rawId: credentialID,
            response: RegistrationCredentialResponseJSON(
                clientDataJSON: Base64URL.encode(credential.rawClientDataJSON),
                attestationObject: Base64URL.encode(credential.rawAttestationObject)
            ),
            type: "public-key",
            clientExtensionResults: EmptyClientExtensionResults(),
            authenticatorAttachment: "platform"
        )
    }

    public static func authenticationCredentialJSON(
        from credential: PlatformAssertionCredential
    ) -> AuthenticationCredentialJSON {
        let credentialID = Base64URL.encode(credential.credentialID)
        return AuthenticationCredentialJSON(
            id: credentialID,
            rawId: credentialID,
            response: AuthenticationCredentialResponseJSON(
                clientDataJSON: Base64URL.encode(credential.rawClientDataJSON),
                authenticatorData: Base64URL.encode(credential.rawAuthenticatorData),
                signature: Base64URL.encode(credential.signature),
                userHandle: credential.userID.map(Base64URL.encode)
            ),
            type: "public-key",
            clientExtensionResults: EmptyClientExtensionResults(),
            authenticatorAttachment: "platform"
        )
    }
}