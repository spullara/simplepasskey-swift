import Foundation
@testable import SimplePasskey

final class InMemoryTokenStore: TokenStore {
    var tokens: StoredTokens?

    init(tokens: StoredTokens? = nil) {
        self.tokens = tokens
    }

    func load() throws -> StoredTokens? {
        tokens
    }

    func save(_ tokens: StoredTokens) throws {
        self.tokens = tokens
    }

    func clear() throws {
        tokens = nil
    }
}

final class MockPasskeyCeremony: PasskeyCeremony {
    var registrationCredential = RegistrationCredentialJSON(
        id: "id",
        rawId: "id",
        response: RegistrationCredentialResponseJSON(
            clientDataJSON: "client",
            attestationObject: "attestation"
        ),
        type: "public-key",
        clientExtensionResults: EmptyClientExtensionResults(),
        authenticatorAttachment: "platform"
    )
    var authenticationCredential = AuthenticationCredentialJSON(
        id: "id",
        rawId: "id",
        response: AuthenticationCredentialResponseJSON(
            clientDataJSON: "client",
            authenticatorData: "authData",
            signature: "signature",
            userHandle: nil
        ),
        type: "public-key",
        clientExtensionResults: EmptyClientExtensionResults(),
        authenticatorAttachment: "platform"
    )

    func performRegistration(options: PublicKeyCredentialCreationOptions) async throws -> RegistrationCredentialJSON {
        registrationCredential
    }

    func performAuthentication(options: PublicKeyCredentialRequestOptions) async throws -> AuthenticationCredentialJSON {
        authenticationCredential
    }
}

final class MockURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, Data))?
    static var requests: [URLRequest] = []

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            Self.requests.append(request)
            let (status, data) = try Self.handler?(request) ?? (404, Data())
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: status,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    static func reset() {
        requests = []
        handler = nil
    }
}

func makeMockSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [MockURLProtocol.self]
    return URLSession(configuration: configuration)
}