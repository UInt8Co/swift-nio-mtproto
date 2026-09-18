/// Public, non-secret channel binding for application authentication proofs.
/// It identifies the live encrypted session without exporting its key material.
public struct MTProtoSessionBinding: Sendable, Equatable {
  public let authKeyID: Int64
  public let sessionID: Int64

  public init(authKeyID: Int64, sessionID: Int64) {
    self.authKeyID = authKeyID
    self.sessionID = sessionID
  }
}
