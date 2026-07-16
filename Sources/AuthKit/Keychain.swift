import Foundation

/// Shared keychain constants. The access group is carried VERBATIM from
/// cookiesync-keyhelper so existing vault items stay readable after the
/// migration — changing it silently re-enrolls every cookiesync user.
/// build-app.sh refuses any Team ID other than SXKCTF23Q2 because this literal
/// must match the signed entitlements at runtime.
public enum Keychain {
    public static let accessGroup = "SXKCTF23Q2.com.yasyf.cookiesync.helper"
    public static let cacheTagPrefix = "authkit.cache."
    public static let attestTag = "authkit.attest"
}

/// Downcasts a keychain result to SecKey after proving its CF type — CF types
/// have no checked conditional cast, so the TypeID guard carries the check.
func secKey(from item: CFTypeRef) throws -> SecKey {
    guard CFGetTypeID(item) == SecKeyGetTypeID() else {
        throw HelperFailure.failed("keychain returned a non-key item")
    }
    return unsafeDowncast(item, to: SecKey.self)
}
