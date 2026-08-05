import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The negotiated result of a completed auth-key handshake.
public struct MTProtoSessionKeys: Equatable, Sendable {
  /// The 256-byte shared auth key.
  public let authKey: Data
  /// `auth_key_id`: the low 64 bits of `SHA1(auth_key)`.
  public let authKeyID: Int64
  /// The initial server salt: `new_nonce[0..8] XOR server_nonce[0..8]`.
  public let serverSalt: Int64
  /// For a PFS *temporary* key (`p_q_inner_data_temp[_dc]`), the unix timestamp
  /// at which it expires (`server_time + expires_in`); `0` for an ordinary
  /// permanent key.
  public let expiresAt: Int32

  public init(authKey: Data, authKeyID: Int64, serverSalt: Int64, expiresAt: Int32 = 0) {
    self.authKey = authKey
    self.authKeyID = authKeyID
    self.serverSalt = serverSalt
    self.expiresAt = expiresAt
  }
}

// MARK: - int128 / int256 byte helpers

/// The 16 little-endian wire bytes of a TL `int128`.
public func int128Data(_ value: TLInt128) -> Data {
  var writer = TLWriter()
  writer.writeInt128(value)
  return writer.data
}

/// The 32 little-endian wire bytes of a TL `int256`.
public func int256Data(_ value: TLInt256) -> Data {
  var writer = TLWriter()
  writer.writeInt256(value)
  return writer.data
}
