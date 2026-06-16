import Foundation
import XCTest
@testable import SimplePasskey

final class SimplePasskeyTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.reset()
        super.tearDown()
    }

    func testBase64URLEncodingAndDecoding() throws {
        let data = Data([251, 255, 238, 250, 1, 2, 3])
        let encoded = Base64URL.encode(data)

        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(try Base64URL.decode(encoded), data)
    }

    func testJWTExpParsingAndNearExpiryDetection() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let token = Self.jwt(exp: Int(now.timeIntervalSince1970) + 30, sub: "user-1")

        XCTAssertEqual(JWT.subject(from: token), "user-1")
        XCTAssertEqual(JWT.expirationDate(from: token), Date(timeIntervalSince1970: 1_700_000_030))
        XCTAssertTrue(JWT.isExpiredOrNearExpiry(token, leeway: 60, now: now))
        XCTAssertFalse(JWT.isExpiredOrNearExpiry(token, leeway: 10, now: now))
    }

    func testGetTokenSilentlyRefreshesExpiredToken() async throws {
        let expired = Self.jwt(exp: 1, sub: "user-1")
        let refreshed = Self.jwt(exp: 4_100_000_000, sub: "user-1")
        let store = InMemoryTokenStore(tokens: StoredTokens(
            jwt: expired,
            userId: "user-1",
            refreshToken: "refresh-old"
        ))
        MockURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/auth/refresh")
            XCTAssertEqual(Self.jsonBody(request)["refreshToken"] as? String, "refresh-old")
            return (200, Self.jsonData([
                "jwt": refreshed,
                "userId": "user-1",
                "refreshToken": "refresh-new",
                "expiresIn": 3600,
            ]))
        }
        let auth = Self.client(store: store)

        let token = try await auth.getToken()

        XCTAssertEqual(token, refreshed)
        XCTAssertEqual(store.tokens?.refreshToken, "refresh-new")
        XCTAssertEqual(MockURLProtocol.requests.count, 1)
    }

    func testAuthedFetchRefreshesOn401AndRetriesOnce() async throws {
        let initial = Self.jwt(exp: 4_100_000_000, sub: "user-1")
        let refreshed = Self.jwt(exp: 4_200_000_000, sub: "user-1")
        let store = InMemoryTokenStore(tokens: StoredTokens(
            jwt: initial,
            userId: "user-1",
            refreshToken: "refresh-old"
        ))
        var protectedHitCount = 0
        MockURLProtocol.handler = { request in
            switch request.url?.path {
            case "/protected":
                protectedHitCount += 1
                let expectedToken = protectedHitCount == 1 ? initial : refreshed
                XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer \(expectedToken)")
                return protectedHitCount == 1
                    ? (401, Self.jsonData(["error": "unauthorized"]))
                    : (200, Self.jsonData(["ok": true]))
            case "/auth/refresh":
                return (200, Self.jsonData([
                    "jwt": refreshed,
                    "userId": "user-1",
                    "refreshToken": "refresh-new",
                ]))
            default:
                return (404, Data())
            }
        }
        let auth = Self.client(store: store)
        let request = URLRequest(url: URL(string: "https://example.test/protected")!)

        let (data, response) = try await auth.authedFetch(request)

        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        XCTAssertEqual((try JSONSerialization.jsonObject(with: data) as? [String: Bool])?["ok"], true)
        XCTAssertEqual(protectedHitCount, 2)
        XCTAssertEqual(MockURLProtocol.requests.map { $0.url?.path }, ["/protected", "/auth/refresh", "/protected"])
    }

    func testRegistrationAndAssertionOptionMapping() throws {
        let challenge = Data("challenge".utf8)
        let userID = Data("user-id".utf8)
        let excludedID = Data("excluded".utf8)
        let creation = PublicKeyCredentialCreationOptions(
            challenge: Base64URL.encode(challenge),
            rp: RelyingParty(name: "SimplePasskey", id: "login.example.com"),
            user: CredentialUser(
                id: Base64URL.encode(userID),
                name: "sam@example.com",
                displayName: "Sam"
            ),
            attestation: "none",
            excludeCredentials: [PublicKeyCredentialDescriptor(
                id: Base64URL.encode(excludedID),
                type: "public-key",
                transports: ["internal"]
            )],
            authenticatorSelection: AuthenticatorSelection(
                residentKey: "required",
                userVerification: "preferred"
            )
        )

        let registration = try WebAuthnMapper.registrationRequestParameters(from: creation)

        XCTAssertEqual(registration.relyingPartyIdentifier, "login.example.com")
        XCTAssertEqual(registration.challenge, challenge)
        XCTAssertEqual(registration.userID, userID)
        XCTAssertEqual(registration.excludedCredentialIDs, [excludedID])

        let request = PublicKeyCredentialRequestOptions(
            challenge: Base64URL.encode(challenge),
            rpId: "login.example.com",
            allowCredentials: [PublicKeyCredentialDescriptor(
                id: Base64URL.encode(excludedID),
                type: "public-key",
                transports: nil
            )],
            userVerification: "preferred"
        )
        let assertion = try WebAuthnMapper.assertionRequestParameters(from: request)

        XCTAssertEqual(assertion.relyingPartyIdentifier, "login.example.com")
        XCTAssertEqual(assertion.challenge, challenge)
        XCTAssertEqual(assertion.allowedCredentialIDs, [excludedID])
    }

    func testCredentialResponseMapping() {
        let registration = WebAuthnMapper.registrationCredentialJSON(from: PlatformRegistrationCredential(
            credentialID: Data("cred".utf8),
            rawClientDataJSON: Data("client".utf8),
            rawAttestationObject: Data("attestation".utf8)
        ))
        XCTAssertEqual(registration.id, Base64URL.encode(Data("cred".utf8)))
        XCTAssertEqual(registration.response.clientDataJSON, Base64URL.encode(Data("client".utf8)))
        XCTAssertEqual(registration.response.attestationObject, Base64URL.encode(Data("attestation".utf8)))

        let authentication = WebAuthnMapper.authenticationCredentialJSON(from: PlatformAssertionCredential(
            credentialID: Data("cred".utf8),
            rawClientDataJSON: Data("client".utf8),
            rawAuthenticatorData: Data("auth".utf8),
            signature: Data("sig".utf8),
            userID: Data("user".utf8)
        ))
        XCTAssertEqual(authentication.id, Base64URL.encode(Data("cred".utf8)))
        XCTAssertEqual(authentication.response.authenticatorData, Base64URL.encode(Data("auth".utf8)))
        XCTAssertEqual(authentication.response.signature, Base64URL.encode(Data("sig".utf8)))
        XCTAssertEqual(authentication.response.userHandle, Base64URL.encode(Data("user".utf8)))
    }

    private static func client(store: TokenStore) -> SimplePasskey {
        SimplePasskey(
            clientId: "client-id",
            baseUrl: URL(string: "https://example.test")!,
            urlSession: makeMockSession(),
            tokenStore: store,
            passkeyCeremony: MockPasskeyCeremony(),
            nearExpiryLeeway: 60
        )
    }

    private static func jwt(exp: Int, sub: String) -> String {
        let header = Base64URL.encode(jsonData(["alg": "none", "typ": "JWT"]))
        let payload = Base64URL.encode(jsonData(["exp": exp, "sub": sub]))
        return "\(header).\(payload).signature"
    }

    private static func jsonData(_ object: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private static func jsonBody(_ request: URLRequest) -> [String: Any] {
        let data: Data
        if let body = request.httpBody {
            data = body
        } else if let stream = request.httpBodyStream {
            var buffer = [UInt8](repeating: 0, count: 1024)
            var collected = Data()
            stream.open()
            defer { stream.close() }
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                collected.append(buffer, count: count)
            }
            data = collected
        } else {
            return [:]
        }
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }
}