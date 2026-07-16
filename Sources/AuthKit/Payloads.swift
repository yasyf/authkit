import Foundation

/// The consent-sign stdin payload. The helper computes the subject digest from
/// `argv` ITSELF and displays the same argv in the sheet — it never accepts a
/// caller-composed reason for attestation (display-digest binding is the spoof
/// defense). `nonce` is base64; the root verifier generated it and checks it.
public struct ConsentSignRequest: Codable, Sendable {
    public let nonce: String
    public let argv: [String]
    public let requestedFrom: String?

    enum CodingKeys: String, CodingKey {
        case nonce
        case argv
        case requestedFrom = "requested_from"
    }

    public init(nonce: String, argv: [String], requestedFrom: String? = nil) {
        self.nonce = nonce
        self.argv = argv
        self.requestedFrom = requestedFrom
    }
}

/// The consent-sign stdout payload: the signing key's ID and the base64 ECDSA
/// signature over nonce ‖ sha256(canonical argv ‖ 0x00 ‖ origin_host).
public struct ConsentSignResponse: Codable, Sendable {
    public let keyID: String
    public let sig: String

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case sig
    }

    public init(keyID: String, sig: String) {
        self.keyID = keyID
        self.sig = sig
    }
}

/// The keygen stdout payload: the Secure-Enclave public key (base64 X9.63) and
/// its key ID, for root-owned enrollment.
public struct KeygenResponse: Codable, Sendable {
    public let keyID: String
    public let publicKey: String

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case publicKey = "public_key"
    }

    public init(keyID: String, publicKey: String) {
        self.keyID = keyID
        self.publicKey = publicKey
    }
}
