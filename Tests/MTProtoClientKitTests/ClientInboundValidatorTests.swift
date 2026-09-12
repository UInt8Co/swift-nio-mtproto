import MTProtoClientKit
import Testing

@Suite struct ClientInboundValidatorTests {
  let now: Int64 = 1_700_000_000

  func id(_ sequence: Int64) -> Int64 { (now << 32) + sequence * 4 + 1 }

  @Test func rejectsReplayAfterEviction() {
    var validator = MTProtoClientInboundValidator(maxTrackedIDs: 2)
    for sequence in 0..<100 {
      #expect(validator.validate(msgID: id(Int64(sequence)), now: now) == nil)
    }
    #expect(validator.validate(msgID: id(0), now: now) == .duplicate)
    #expect(validator.validate(msgID: id(98), now: now) == .duplicate)
  }

  @Test func retainsHighestIDsDespiteReordering() {
    var validator = MTProtoClientInboundValidator(maxTrackedIDs: 2)
    #expect(validator.validate(msgID: id(3), now: now) == nil)
    #expect(validator.validate(msgID: id(1), now: now) == nil)
    #expect(validator.validate(msgID: id(2), now: now) == nil)
    #expect(validator.validate(msgID: id(0), now: now) == .duplicate)
    #expect(validator.validate(msgID: id(1), now: now) == .duplicate)
    #expect(validator.validate(msgID: id(3), now: now) == .duplicate)
    validator.reset()
    #expect(validator.validate(msgID: id(0), now: now) == nil)
  }

  @Test func shrinkingWindowPreservesReplayProtection() {
    var validator = MTProtoClientInboundValidator(maxTrackedIDs: 100)
    for sequence in 0..<100 {
      #expect(validator.validate(msgID: id(Int64(sequence)), now: now) == nil)
    }
    validator.maxTrackedIDs = 1
    #expect(validator.validate(msgID: id(100), now: now) == nil)
    #expect(validator.validate(msgID: id(99), now: now) == .duplicate)
  }
}
