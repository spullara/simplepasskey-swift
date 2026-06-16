# SimplePasskey Swift SDK

[![CI](https://github.com/spullara/simplepasskey-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/spullara/simplepasskey-swift/actions/workflows/ci.yml)

Official native Swift package for SimplePasskey passkey authentication on iOS and macOS.

The SDK mirrors the browser SDK shape while using Apple's native passkey APIs and storing session tokens in the Keychain.

## Requirements

- iOS 16+ or macOS 13+
- Swift Package Manager
- Associated Domains configured for the relying party ID used by your SimplePasskey tenant

## Installation

Add this package to your app in Xcode:

1. Open **File → Add Package Dependencies...**
2. Enter the package URL for this repository.
3. Select the `SimplePasskey` product.

## Usage

```swift
import Foundation
import SimplePasskey

let auth = SimplePasskey(clientId: "your-client-id")

// Register a new user.
let registration = try await auth.register(displayName: "Sam")
print(registration.userId)

// Sign in. If a stored refresh token can restore the session, this refreshes
// silently before falling back to a passkey prompt.
let signIn = try await auth.signIn()
print(signIn.jwt)

// Read auth state.
if auth.isAuthenticated {
    print("Logged in as", auth.currentSession?.userId ?? "unknown")
}

// Get a valid access token. Expired or near-expiry tokens are refreshed.
let token = try await auth.getToken()

// Fetch with Authorization: Bearer. A 401 refreshes once and retries once.
let request = URLRequest(url: URL(string: "https://api.example.com/me")!)
let (data, response) = try await auth.authedFetch(request)

// Logout clears local Keychain state and revokes the refresh token server-side.
await auth.logout()
```

By default, `baseUrl` is `https://api.simplepasskey.com`:

```swift
let auth = SimplePasskey(
    clientId: "your-client-id",
    baseUrl: URL(string: "https://api.simplepasskey.com")!
)
```

## API

### `SimplePasskey(clientId:baseUrl:)`

Creates an SDK instance and restores any stored access token and refresh token from the Keychain.

### `register(displayName:) async throws -> AuthResult`

Requests `/register/options`, performs a native platform passkey registration with `ASAuthorizationPlatformPublicKeyCredentialProvider`, verifies it with `/register/verify`, stores returned tokens, and returns `{ jwt, userId, refreshToken, expiresIn }`.

### `signIn() async throws -> AuthResult`

Returns the current valid session if present. Otherwise it tries silent refresh with the Keychain refresh token before prompting for a passkey and verifying against `/auth/verify`.

### `getToken() async throws -> String`

Returns a valid access token. If the token is expired or within the refresh leeway, the SDK calls `/auth/refresh` with `{ refreshToken }`, stores the rotated refresh token, and returns the new JWT.

### `authedFetch(_:) async throws -> (Data, URLResponse)`

Adds `Authorization: Bearer <jwt>` to a `URLRequest`. If the response is `401`, the SDK refreshes once and retries the original request once.

### `logout() async`

Best-effort call to `/auth/logout` with `{ refreshToken }`, then clears local Keychain state.

### `currentSession` and `isAuthenticated`

Use `currentSession` to inspect the restored session and `isAuthenticated` to check whether the access token is currently unexpired.

## Associated Domains and AASA

Native passkeys require the app, relying party ID, and verified web domain to line up:

1. Enable the **Associated Domains** capability in your app target.
2. Add an entry for your tenant relying party ID, for example:

   ```text
   webcredentials:login.example.com
   ```

3. Host an `apple-app-site-association` file on that domain that lists your app identifier under `webcredentials.apps`.
4. Configure the same relying party ID and allowed native origin/domain in SimplePasskey.

The live passkey ceremony must be tested on a real device or properly configured simulator/account. Unit tests in this package cover the non-UI mapping and token lifecycle logic.

## Token Storage

The SDK stores the access token and refresh token in the Keychain using `KeychainTokenStore`. Refresh tokens are sent only in JSON request bodies to `/auth/refresh` and `/auth/logout`; they are not placed in URLs.

For tests, inject a custom `TokenStore` and `URLSessionProtocol` through the internal initializer used by this package's test target.

## Verification

Run:

```bash
swift build
swift test
```
## License

[MIT](LICENSE) © Sam Pullara
