@testable import AuthKit
import Foundation
import Testing

@Test func consentSignRequestDecodesSnakeCaseFields() throws {
    let body = Data(#"{"nonce":"AAEC","argv":["ls","-la"],"requested_from":"studio"}"#.utf8)
    let request = try JSONDecoder().decode(ConsentSignRequest.self, from: body)
    #expect(request.nonce == "AAEC")
    #expect(request.argv == ["ls", "-la"])
    #expect(request.requestedFrom == "studio")
}

@Test func consentSignRequestAllowsAMissingRequestedFrom() throws {
    let body = Data(#"{"nonce":"AAEC","argv":["ls"]}"#.utf8)
    let request = try JSONDecoder().decode(ConsentSignRequest.self, from: body)
    #expect(request.requestedFrom == nil)
}

@Test func consentSignResponseEncodesTheWireShape() throws {
    let data = try JSONEncoder().encode(ConsentSignResponse(keyID: "abc", sig: "c2ln"))
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: String])
    #expect(object == ["key_id": "abc", "sig": "c2ln"])
}

@Test func keygenResponseEncodesTheWireShape() throws {
    let data = try JSONEncoder().encode(KeygenResponse(keyID: "abc", publicKey: "cHVi"))
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: String])
    #expect(object == ["key_id": "abc", "public_key": "cHVi"])
}

@Test func batchLinesFollowTheTabSeparatedContract() {
    #expect(Vault.batchLine(0, "ok", "c2VjcmV0") == "0\tok\tc2VjcmV0\n")
    #expect(Vault.batchLine(2, "missing", "-") == "2\tmissing\t-\n")
}
