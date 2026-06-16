import Foundation

public enum JWT {
    public static func payload(from token: String) -> [String: Any]? {
        let parts = token.split(separator: ".")
        guard parts.count >= 2 else { return nil }

        do {
            let data = try Base64URL.decode(String(parts[1]))
            return try JSONSerialization.jsonObject(with: data) as? [String: Any]
        } catch {
            return nil
        }
    }

    public static func subject(from token: String) -> String? {
        payload(from: token)?["sub"] as? String
    }

    public static func expirationDate(from token: String) -> Date? {
        guard let exp = payload(from: token)?["exp"] else { return nil }

        if let seconds = exp as? TimeInterval {
            return Date(timeIntervalSince1970: seconds)
        }
        if let number = exp as? NSNumber {
            return Date(timeIntervalSince1970: number.doubleValue)
        }
        return nil
    }

    public static func isExpiredOrNearExpiry(
        _ token: String,
        leeway: TimeInterval = 60,
        now: Date = Date()
    ) -> Bool {
        guard let expiration = expirationDate(from: token) else { return true }
        return expiration.timeIntervalSince(now) <= leeway
    }
}