import XCTest
import SwiftProtobuf
@testable import ProPresenterProtos

final class ProtoEnumTests: XCTestCase {

    // MARK: - AlphaType enum

    func testAlphaTypeDefaultValue() {
        let value = Rv_Data_AlphaType()
        XCTAssertEqual(value, .unknown)
        XCTAssertEqual(value.rawValue, 0)
    }

    func testAlphaTypeRawValues() {
        XCTAssertEqual(Rv_Data_AlphaType.unknown.rawValue, 0)
        XCTAssertEqual(Rv_Data_AlphaType.straight.rawValue, 1)
        XCTAssertEqual(Rv_Data_AlphaType.premultiplied.rawValue, 2)
    }

    func testAlphaTypeInitFromRawValue() {
        XCTAssertEqual(Rv_Data_AlphaType(rawValue: 0), .unknown)
        XCTAssertEqual(Rv_Data_AlphaType(rawValue: 1), .straight)
        XCTAssertEqual(Rv_Data_AlphaType(rawValue: 2), .premultiplied)
    }

    func testAlphaTypeUnrecognizedValue() {
        let value = Rv_Data_AlphaType(rawValue: 999)
        XCTAssertNotNil(value)
        XCTAssertEqual(value?.rawValue, 999)
    }

    func testAlphaTypeAllCases() {
        XCTAssertEqual(Rv_Data_AlphaType.allCases.count, 3)
        XCTAssertTrue(Rv_Data_AlphaType.allCases.contains(.unknown))
        XCTAssertTrue(Rv_Data_AlphaType.allCases.contains(.straight))
        XCTAssertTrue(Rv_Data_AlphaType.allCases.contains(.premultiplied))
    }

    // MARK: - Nested enum (AlignmentGuide.GuidelineOrientation)

    func testGuidelineOrientationValues() {
        XCTAssertEqual(Rv_Data_AlignmentGuide.GuidelineOrientation.horizontal.rawValue, 0)
        XCTAssertEqual(Rv_Data_AlignmentGuide.GuidelineOrientation.vertical.rawValue, 1)
    }

    func testGuidelineOrientationAllCases() {
        XCTAssertEqual(Rv_Data_AlignmentGuide.GuidelineOrientation.allCases.count, 2)
    }
}

final class ProtoMessageTests: XCTestCase {

    // MARK: - UUID message

    func testUUIDDefaultValues() {
        let uuid = Rv_Data_UUID()
        XCTAssertEqual(uuid.string, "")
    }

    func testUUIDSetFields() {
        var uuid = Rv_Data_UUID()
        uuid.string = "abc-123"
        XCTAssertEqual(uuid.string, "abc-123")
    }

    func testUUIDEquality() {
        var a = Rv_Data_UUID()
        a.string = "same"
        var b = Rv_Data_UUID()
        b.string = "same"
        XCTAssertEqual(a, b)

        b.string = "different"
        XCTAssertNotEqual(a, b)
    }

    // MARK: - Color message

    func testColorDefaultValues() {
        let color = Rv_Data_Color()
        XCTAssertEqual(color.red, 0)
        XCTAssertEqual(color.green, 0)
        XCTAssertEqual(color.blue, 0)
        XCTAssertEqual(color.alpha, 0)
    }

    func testColorSetFields() {
        var color = Rv_Data_Color()
        color.red = 1.0
        color.green = 0.5
        color.blue = 0.25
        color.alpha = 0.8
        XCTAssertEqual(color.red, 1.0)
        XCTAssertEqual(color.green, 0.5)
        XCTAssertEqual(color.blue, 0.25)
        XCTAssertEqual(color.alpha, 0.8)
    }

    func testColorEquality() {
        var a = Rv_Data_Color()
        a.red = 1.0
        a.green = 0.0
        a.blue = 0.0
        a.alpha = 1.0

        var b = Rv_Data_Color()
        b.red = 1.0
        b.green = 0.0
        b.blue = 0.0
        b.alpha = 1.0
        XCTAssertEqual(a, b)

        b.blue = 0.5
        XCTAssertNotEqual(a, b)
    }

    // MARK: - AlignmentGuide (nested enum + message reference)

    func testAlignmentGuideDefaultValues() {
        let guide = Rv_Data_AlignmentGuide()
        XCTAssertFalse(guide.hasUuid)
        XCTAssertEqual(guide.orientation, .horizontal)
        XCTAssertEqual(guide.location, 0)
    }

    func testAlignmentGuideSetFields() {
        var guide = Rv_Data_AlignmentGuide()
        var uuid = Rv_Data_UUID()
        uuid.string = "guide-1"
        guide.uuid = uuid
        guide.orientation = .vertical
        guide.location = 42.5

        XCTAssertTrue(guide.hasUuid)
        XCTAssertEqual(guide.uuid.string, "guide-1")
        XCTAssertEqual(guide.orientation, .vertical)
        XCTAssertEqual(guide.location, 42.5)
    }

    func testAlignmentGuideClearUuid() {
        var guide = Rv_Data_AlignmentGuide()
        guide.uuid = Rv_Data_UUID()
        XCTAssertTrue(guide.hasUuid)

        guide.clearUuid()
        XCTAssertFalse(guide.hasUuid)
    }

    // MARK: - AdvertisementGroup (cross-message references)

    func testAdvertisementGroupDefaultValues() {
        let group = Rv_Data_AdvertisementGroup()
        XCTAssertFalse(group.hasUuid)
        XCTAssertEqual(group.name, "")
        XCTAssertFalse(group.hasURL)
        XCTAssertEqual(group.startIndex, 0)
        XCTAssertEqual(group.duration, 0)
    }

    func testAdvertisementGroupSetFields() {
        var group = Rv_Data_AdvertisementGroup()
        var uuid = Rv_Data_UUID()
        uuid.string = "ad-group-1"
        group.uuid = uuid
        group.name = "Test Group"
        group.startIndex = 5
        group.duration = 30.0

        XCTAssertEqual(group.uuid.string, "ad-group-1")
        XCTAssertEqual(group.name, "Test Group")
        XCTAssertEqual(group.startIndex, 5)
        XCTAssertEqual(group.duration, 30.0)
    }
}

final class ProtoSerializationTests: XCTestCase {

    // MARK: - Binary protobuf round-trip

    func testUUIDBinaryRoundTrip() throws {
        var original = Rv_Data_UUID()
        original.string = "test-uuid-123"

        let data = try original.serializedData()
        let decoded = try Rv_Data_UUID(serializedBytes: data)
        XCTAssertEqual(original, decoded)
    }

    func testColorBinaryRoundTrip() throws {
        var original = Rv_Data_Color()
        original.red = 0.1
        original.green = 0.2
        original.blue = 0.3
        original.alpha = 1.0

        let data = try original.serializedData()
        let decoded = try Rv_Data_Color(serializedBytes: data)
        XCTAssertEqual(original, decoded)
    }

    func testAlignmentGuideBinaryRoundTrip() throws {
        var original = Rv_Data_AlignmentGuide()
        var uuid = Rv_Data_UUID()
        uuid.string = "guide-uuid"
        original.uuid = uuid
        original.orientation = .vertical
        original.location = 100.5

        let data = try original.serializedData()
        let decoded = try Rv_Data_AlignmentGuide(serializedBytes: data)
        XCTAssertEqual(original, decoded)
        XCTAssertEqual(decoded.uuid.string, "guide-uuid")
        XCTAssertEqual(decoded.orientation, Rv_Data_AlignmentGuide.GuidelineOrientation.vertical)
        XCTAssertEqual(decoded.location, 100.5)
    }

    func testAdvertisementGroupBinaryRoundTrip() throws {
        var original = Rv_Data_AdvertisementGroup()
        var uuid = Rv_Data_UUID()
        uuid.string = "ad-uuid"
        original.uuid = uuid
        original.name = "My Ad Group"
        original.startIndex = 3
        original.duration = 60.0

        let data = try original.serializedData()
        let decoded = try Rv_Data_AdvertisementGroup(serializedBytes: data)
        XCTAssertEqual(original, decoded)
    }

    // MARK: - JSON round-trip

    func testUUIDJsonRoundTrip() throws {
        var original = Rv_Data_UUID()
        original.string = "json-uuid-456"

        let json = try original.jsonString()
        let decoded = try Rv_Data_UUID(jsonString: json)
        XCTAssertEqual(original, decoded)
    }

    func testColorJsonRoundTrip() throws {
        var original = Rv_Data_Color()
        original.red = 1.0
        original.green = 0.0
        original.blue = 0.5
        original.alpha = 0.75

        let json = try original.jsonString()
        let decoded = try Rv_Data_Color(jsonString: json)
        XCTAssertEqual(original, decoded)
    }

    func testAlignmentGuideJsonRoundTrip() throws {
        var original = Rv_Data_AlignmentGuide()
        var uuid = Rv_Data_UUID()
        uuid.string = "json-guide"
        original.uuid = uuid
        original.orientation = .horizontal
        original.location = 250.0

        let json = try original.jsonString()
        let decoded = try Rv_Data_AlignmentGuide(jsonString: json)
        XCTAssertEqual(original, decoded)
    }

    // MARK: - Empty message serialization

    func testEmptyMessageRoundTrip() throws {
        let original = Rv_Data_UUID()
        let data = try original.serializedData()
        let decoded = try Rv_Data_UUID(serializedBytes: data)
        XCTAssertEqual(original, decoded)
        XCTAssertEqual(decoded.string, "")
    }

    // MARK: - Proto message name

    func testProtoMessageNames() {
        XCTAssertEqual(Rv_Data_UUID.protoMessageName, "rv.data.UUID")
        XCTAssertEqual(Rv_Data_Color.protoMessageName, "rv.data.Color")
        XCTAssertEqual(Rv_Data_AlignmentGuide.protoMessageName, "rv.data.AlignmentGuide")
        XCTAssertEqual(Rv_Data_AdvertisementGroup.protoMessageName, "rv.data.AdvertisementGroup")
    }
}
