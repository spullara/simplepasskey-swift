import Foundation

public final class SimplePasskey {
    public static let defaultBaseURL = URL(string: "https://api.simplepasskey.com")!

    private let clientId: String
    private let httpClient: HTTPClient
    private let tokenStore: TokenStore
    private let passkeyCeremony: PasskeyCeremony
    private let nearExpiryLeeway: TimeInterval
    private var session: Session?

    public var currentSession: Session? {
        session
    }

    public var isAuthenticated: Bool {
        guard let session else { return false }
        return !session.isExpired
    }

    public convenience init(
        clientId: String,
        baseUrl: URL = SimplePasskey.defaultBaseURL
    ) {
        self.init(
            clientId: clientId,
            baseUrl: baseUrl,
            urlSession: URLSession.shared,
            tokenStore: KeychainTokenStore(account: clientId),
            passkeyCeremony: ASAuthorizationPasskeyCeremony()
        )
    }

    public init(
        clientId: String,
        baseUrl: URL = SimplePasskey.defaultBaseURL,
        urlSession: URLSessionProtocol,
        tokenStore: TokenStore,
        passkeyCeremony: PasskeyCeremony,
        nearExpiryLeeway: TimeInterval = 60
    ) {
        self.clientId = clientId
        self.httpClient = HTTPClient(
            baseURL: baseUrl.absoluteString.hasSuffix("/") ? baseUrl.deletingLastPathComponent() : baseUrl,
            session: urlSession
        )
        self.tokenStore = tokenStore
        self.passkeyCeremony = passkeyCeremony
        self.nearExpiryLeeway = nearExpiryLeeway
        self.session = (try? tokenStore.load()).flatMap(Self.session(from:))
    }

    public func register(displayName: String? = nil) async throws -> AuthResult {
        let envelope: OptionsEnvelope<PublicKeyCredentialCreationOptions> = try await httpClient.post(
            "/register/options",
            body: RegistrationOptionsRequest(clientId: clientId, displayName: displayName)
        )
        let credential = try await passkeyCeremony.performRegistration(options: envelope.options)
        let payload: AuthResultPayload = try await httpClient.post(
            "/register/verify",
            body: VerifyRequest(token: envelope.token, credential: credential)
        )
        return try apply(payload: payload, fallbackUserId: envelope.userId)
    }

    public func signIn() async throws -> AuthResult {
        if let session, !session.isExpired {
            return AuthResult(
                jwt: session.jwt,
                userId: session.userId ?? JWT.subject(from: session.jwt) ?? "",
                refreshToken: session.refreshToken,
                expiresIn: nil
            )
        }

        if session?.refreshToken != nil || (try? tokenStore.load()?.refreshToken) != nil {
            do {
                let jwt = try await getToken()
                return AuthResult(
                    jwt: jwt,
                    userId: currentSession?.userId ?? JWT.subject(from: jwt) ?? "",
                    refreshToken: currentSession?.refreshToken,
                    expiresIn: nil
                )
            } catch {
                // Fall through to a passkey ceremony when silent refresh is unavailable.
            }
        }

        let envelope: OptionsEnvelope<PublicKeyCredentialRequestOptions> = try await httpClient.post(
            "/auth/options",
            body: ClientIdRequest(clientId: clientId)
        )
        let credential = try await passkeyCeremony.performAuthentication(options: envelope.options)
        let payload: AuthResultPayload = try await httpClient.post(
            "/auth/verify",
            body: VerifyRequest(token: envelope.token, credential: credential)
        )
        return try apply(payload: payload, fallbackUserId: envelope.userId)
    }

    public func getToken() async throws -> String {
        if let session, !session.isExpiredOrNearExpiry(leeway: nearExpiryLeeway) {
            return session.jwt
        }
        return try await refreshAccessToken()
    }

    public func authedFetch(_ request: URLRequest) async throws -> (Data, URLResponse) {
        var firstRequest = request
        firstRequest.setValue("Bearer \(try await getToken())", forHTTPHeaderField: "Authorization")
        let firstResponse = try await httpClient.data(for: firstRequest)

        guard (firstResponse.1 as? HTTPURLResponse)?.statusCode == 401 else {
            return firstResponse
        }

        let newToken = try await refreshAccessToken()
        var retryRequest = request
        retryRequest.setValue("Bearer \(newToken)", forHTTPHeaderField: "Authorization")
        return try await httpClient.data(for: retryRequest)
    }

    public func logout() async {
        let refreshToken = session?.refreshToken ?? (try? tokenStore.load()?.refreshToken) ?? nil
        if let refreshToken {
            let _: EmptyResponse? = try? await httpClient.post(
                "/auth/logout",
                body: RefreshRequest(refreshToken: refreshToken)
            )
        }
        clearSession()
    }

    private func refreshAccessToken() async throws -> String {
        let stored = try tokenStore.load()
        let refreshToken = session?.refreshToken ?? stored?.refreshToken
        guard refreshToken != nil else {
            clearSession()
            throw SimplePasskeyError.missingRefreshToken
        }

        do {
            let payload: AuthResultPayload = try await httpClient.post(
                "/auth/refresh",
                body: RefreshRequest(refreshToken: refreshToken)
            )
            let result = try apply(payload: payload, fallbackUserId: stored?.userId)
            return result.jwt
        } catch {
            clearSession()
            throw error
        }
    }

    private func apply(payload: AuthResultPayload, fallbackUserId: String?) throws -> AuthResult {
        let userId = payload.userId ?? JWT.subject(from: payload.jwt) ?? fallbackUserId ?? ""
        let refreshToken = payload.refreshToken ?? session?.refreshToken
        let tokens = StoredTokens(jwt: payload.jwt, userId: userId, refreshToken: refreshToken)
        try tokenStore.save(tokens)
        session = Self.session(from: tokens)
        return AuthResult(
            jwt: payload.jwt,
            userId: userId,
            refreshToken: refreshToken,
            expiresIn: payload.expiresIn
        )
    }

    private func clearSession() {
        try? tokenStore.clear()
        session = nil
    }

    private static func session(from tokens: StoredTokens) -> Session {
        Session(
            jwt: tokens.jwt,
            userId: tokens.userId ?? JWT.subject(from: tokens.jwt),
            refreshToken: tokens.refreshToken,
            expiresAt: JWT.expirationDate(from: tokens.jwt)
        )
    }
}

private struct EmptyResponse: Decodable {}