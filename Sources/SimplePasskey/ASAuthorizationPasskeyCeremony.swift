import AuthenticationServices
import Foundation

public protocol PasskeyCeremony: AnyObject {
    func performRegistration(options: PublicKeyCredentialCreationOptions) async throws -> RegistrationCredentialJSON
    func performAuthentication(options: PublicKeyCredentialRequestOptions) async throws -> AuthenticationCredentialJSON
}

public final class ASAuthorizationPasskeyCeremony: NSObject, PasskeyCeremony {
    private var activeDelegate: AuthorizationDelegate?

    public override init() {}

    public func performRegistration(
        options: PublicKeyCredentialCreationOptions
    ) async throws -> RegistrationCredentialJSON {
        let parameters = try WebAuthnMapper.registrationRequestParameters(from: options)
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: parameters.relyingPartyIdentifier
        )
        let request = provider.createCredentialRegistrationRequest(
            challenge: parameters.challenge,
            name: parameters.name,
            userID: parameters.userID
        )
        request.displayName = parameters.displayName

        return try await run(requests: [request]) { authorization in
            guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
                throw SimplePasskeyError.unexpectedCredential
            }
            return WebAuthnMapper.registrationCredentialJSON(from: PlatformRegistrationCredential(
                credentialID: credential.credentialID,
                rawClientDataJSON: credential.rawClientDataJSON,
                rawAttestationObject: credential.rawAttestationObject ?? Data()
            ))
        }
    }

    public func performAuthentication(
        options: PublicKeyCredentialRequestOptions
    ) async throws -> AuthenticationCredentialJSON {
        let parameters = try WebAuthnMapper.assertionRequestParameters(from: options)
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: parameters.relyingPartyIdentifier
        )
        let request = provider.createCredentialAssertionRequest(challenge: parameters.challenge)

        return try await run(requests: [request]) { authorization in
            guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
                throw SimplePasskeyError.unexpectedCredential
            }
            return WebAuthnMapper.authenticationCredentialJSON(from: PlatformAssertionCredential(
                credentialID: credential.credentialID,
                rawClientDataJSON: credential.rawClientDataJSON,
                rawAuthenticatorData: credential.rawAuthenticatorData,
                signature: credential.signature,
                userID: credential.userID
            ))
        }
    }

    @MainActor
    private func run<T>(
        requests: [ASAuthorizationRequest],
        mapper: @escaping (ASAuthorization) throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let controller = ASAuthorizationController(authorizationRequests: requests)
            let delegate = AuthorizationDelegate { [weak self] result in
                self?.activeDelegate = nil
                continuation.resume(with: result.flatMap { authorization in
                    Result { try mapper(authorization) }
                })
            }
            activeDelegate = delegate
            controller.delegate = delegate
            controller.performRequests()
        }
    }
}

private final class AuthorizationDelegate: NSObject, ASAuthorizationControllerDelegate {
    private let completion: (Result<ASAuthorization, Error>) -> Void

    init(completion: @escaping (Result<ASAuthorization, Error>) -> Void) {
        self.completion = completion
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        completion(.success(authorization))
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        completion(.failure(error))
    }
}