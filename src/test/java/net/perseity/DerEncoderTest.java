package net.perseity;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for DerEncoder, verifying correct ASN.1/DER encoding for each
 * supported type. Tests validate both the TLV structure (tag, length, value)
 * and specific byte values against known-correct encodings from the X.690 spec.
 */
class DerEncoderTest {

    // -------------------------------------------------------------------------
    // encodeInteger
    // -------------------------------------------------------------------------

    @Test
    void testEncodeIntegerZero() {
        // INTEGER 0 encodes as: tag=0x02, length=0x01, value=0x00
        byte[] encoded = DerEncoder.encodeInteger(BigInteger.ZERO);
        assertArrayEquals(new byte[]{0x02, 0x01, 0x00}, encoded);
    }

    @Test
    void testEncodeIntegerSmallPositive() {
        // INTEGER 1 encodes as: tag=0x02, length=0x01, value=0x01
        byte[] encoded = DerEncoder.encodeInteger(BigInteger.ONE);
        assertArrayEquals(new byte[]{0x02, 0x01, 0x01}, encoded);
    }

    @Test
    void testEncodeIntegerRequiresSignPadding() {
        // 128 (0x80) has its high bit set, which would look negative in signed encoding.
        // BigInteger.toByteArray() prepends 0x00 to preserve the positive sign.
        // Expected: tag=0x02, length=0x02, value=[0x00, 0x80]
        byte[] encoded = DerEncoder.encodeInteger(BigInteger.valueOf(128));
        assertArrayEquals(new byte[]{0x02, 0x02, 0x00, (byte) 0x80}, encoded);
    }

    @Test
    void testEncodeIntegerMultiByteValue() {
        // 65537 = 0x010001, 3 bytes, high bit clear — no sign padding needed
        // Expected: tag=0x02, length=0x03, value=[0x01, 0x00, 0x01]
        byte[] encoded = DerEncoder.encodeInteger(BigInteger.valueOf(65537));
        assertArrayEquals(new byte[]{0x02, 0x03, 0x01, 0x00, 0x01}, encoded);
    }

    // -------------------------------------------------------------------------
    // encodeOid
    // -------------------------------------------------------------------------

    @Test
    void testEncodeOidSimple() {
        // OID 1.2.3:
        //   First two arcs: 40*1 + 2 = 42 = 0x2A
        //   Third arc:      3 = 0x03
        // Expected: tag=0x06, length=0x02, value=[0x2A, 0x03]
        byte[] encoded = DerEncoder.encodeOid("1.2.3");
        assertArrayEquals(new byte[]{0x06, 0x02, 0x2A, 0x03}, encoded);
    }

    @Test
    void testEncodeOidSha256() {
        // OID 2.16.840.1.101.3.4.2.1 (id-sha256)
        // First two arcs: 40*2 + 16 = 96 = 0x60
        // 840 in base-128: (6|0x80)=0x86, 72=0x48
        // 1   = 0x01
        // 101 = 0x65  (< 128, single byte)
        // 3   = 0x03
        // 4   = 0x04
        // 2   = 0x02
        // 1   = 0x01
        byte[] encoded = DerEncoder.encodeOid("2.16.840.1.101.3.4.2.1");
        byte[] expected = {
            0x06, 0x09,
            0x60,                   // 2.16
            (byte) 0x86, 0x48,      // 840
            0x01,                   // 1
            0x65,                   // 101
            0x03, 0x04, 0x02, 0x01  // 3.4.2.1
        };
        assertArrayEquals(expected, encoded);
    }

    @Test
    void testEncodeOidRsassaPss() {
        // OID 1.2.840.113549.1.1.10 (id-RSASSA-PSS)
        // First two arcs: 40*1 + 2 = 42 = 0x2A
        // 840:    (6|0x80)=0x86, 72=0x48
        // 113549: (6|0x80)=0x86, (119|0x80)=0xF7, 13=0x0D
        //         Verify: 6*16384 + 119*128 + 13 = 98304 + 15232 + 13 = 113549 ✓
        // 1:      0x01
        // 1:      0x01
        // 10:     0x0A
        byte[] encoded = DerEncoder.encodeOid("1.2.840.113549.1.1.10");
        byte[] expected = {
            0x06, 0x09,
            0x2A,                               // 1.2
            (byte) 0x86, 0x48,                  // 840
            (byte) 0x86, (byte) 0xF7, 0x0D,     // 113549
            0x01, 0x01, 0x0A                    // 1.1.10
        };
        assertArrayEquals(expected, encoded);
    }

    // -------------------------------------------------------------------------
    // encodeBitString
    // -------------------------------------------------------------------------

    @Test
    void testEncodeBitStringPrependsUnusedBitsByte() {
        // BIT STRING encoding always prepends a 0x00 "unused bits" byte before the content.
        // Input: [0x01, 0x02]
        // Expected: tag=0x03, length=0x03, value=[0x00, 0x01, 0x02]
        byte[] encoded = DerEncoder.encodeBitString(new byte[]{0x01, 0x02});
        assertArrayEquals(new byte[]{0x03, 0x03, 0x00, 0x01, 0x02}, encoded);
    }

    @Test
    void testEncodeBitStringEmpty() {
        // An empty byte array produces just the unused-bits prefix byte.
        // Expected: tag=0x03, length=0x01, value=[0x00]
        byte[] encoded = DerEncoder.encodeBitString(new byte[]{});
        assertArrayEquals(new byte[]{0x03, 0x01, 0x00}, encoded);
    }

    // -------------------------------------------------------------------------
    // encodeNull
    // -------------------------------------------------------------------------

    @Test
    void testEncodeNull() {
        // NULL always encodes as exactly two bytes: tag=0x05, length=0x00
        assertArrayEquals(new byte[]{0x05, 0x00}, DerEncoder.encodeNull());
    }

    // -------------------------------------------------------------------------
    // encodeSequence
    // -------------------------------------------------------------------------

    @Test
    void testEncodeSequenceEmpty() {
        // An empty SEQUENCE has tag=0x30, length=0x00, no content
        byte[] encoded = DerEncoder.encodeSequence();
        assertArrayEquals(new byte[]{0x30, 0x00}, encoded);
    }

    @Test
    void testEncodeSequenceSingleElement() {
        // Wrapping [0x01, 0x02] in a SEQUENCE:
        // Expected: tag=0x30, length=0x02, content=[0x01, 0x02]
        byte[] encoded = DerEncoder.encodeSequence(new byte[]{0x01, 0x02});
        assertArrayEquals(new byte[]{0x30, 0x02, 0x01, 0x02}, encoded);
    }

    @Test
    void testEncodeSequenceMultipleElements() {
        // Elements are concatenated in order inside the SEQUENCE.
        // [0x01, 0x02] + [0x03, 0x04] → content = [0x01, 0x02, 0x03, 0x04]
        // Expected: tag=0x30, length=0x04, content=[0x01, 0x02, 0x03, 0x04]
        byte[] encoded = DerEncoder.encodeSequence(
                new byte[]{0x01, 0x02},
                new byte[]{0x03, 0x04});
        assertArrayEquals(new byte[]{0x30, 0x04, 0x01, 0x02, 0x03, 0x04}, encoded);
    }

    @Test
    void testEncodeSequenceLongFormLength() {
        // When content length >= 128, DER uses long-form length encoding.
        // 200 bytes of content → length field = [0x81, 0xC8] (0x81 = 0x80|1 byte, 0xC8 = 200)
        byte[] content = new byte[200];
        Arrays.fill(content, (byte) 0xFF);

        byte[] encoded = DerEncoder.encodeSequence(content);

        assertEquals(0x30, encoded[0] & 0xFF);     // SEQUENCE tag
        assertEquals(0x81, encoded[1] & 0xFF);     // long-form: 1 length byte follows
        assertEquals(200,  encoded[2] & 0xFF);     // length = 200
        assertEquals(3 + 200, encoded.length);     // tag + 2-byte length + 200 content bytes
    }

    // -------------------------------------------------------------------------
    // encodeExplicitTag
    // -------------------------------------------------------------------------

    @Test
    void testEncodeExplicitTagZero() {
        // [0] EXPLICIT wrapping [0x01]: tag byte = 0xA0 | 0 = 0xA0
        // Expected: [0xA0, 0x01, 0x01]
        byte[] encoded = DerEncoder.encodeExplicitTag(0, new byte[]{0x01});
        assertArrayEquals(new byte[]{(byte) 0xA0, 0x01, 0x01}, encoded);
    }

    @Test
    void testEncodeExplicitTagNonZero() {
        // [2] EXPLICIT wrapping [0x05, 0x00] (a NULL): tag byte = 0xA0 | 2 = 0xA2
        // Expected: [0xA2, 0x02, 0x05, 0x00]
        byte[] encoded = DerEncoder.encodeExplicitTag(2, new byte[]{0x05, 0x00});
        assertArrayEquals(new byte[]{(byte) 0xA2, 0x02, 0x05, 0x00}, encoded);
    }

    // -------------------------------------------------------------------------
    // encodeUtcTime
    // -------------------------------------------------------------------------

    @Test
    void testEncodeUtcTimeFormat() throws Exception {
        // UTCTime must be ASCII-encoded as YYMMDDhhmmssZ in UTC.
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = sdf.parse("260101120000"); // 2026-01-01 12:00:00 UTC

        byte[] encoded = DerEncoder.encodeUtcTime(date);

        assertEquals(0x17, encoded[0] & 0xFF); // UTCTime tag
        String value = new String(encoded, 2, encoded[1], java.nio.charset.StandardCharsets.US_ASCII);
        assertEquals("260101120000Z", value);
    }

    @Test
    void testEncodeUtcTimeIsUtc() throws Exception {
        // The encoded time must be UTC regardless of the JVM's local timezone.
        // Use a fixed UTC instant and verify the Z suffix and UTC hours.
        SimpleDateFormat utcSdf = new SimpleDateFormat("yyMMddHHmmss");
        utcSdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = utcSdf.parse("260615090000"); // 2026-06-15 09:00:00 UTC

        byte[] encoded = DerEncoder.encodeUtcTime(date);

        String value = new String(encoded, 2, encoded[1], java.nio.charset.StandardCharsets.US_ASCII);
        assertTrue(value.endsWith("Z"), "UTCTime must end with 'Z' (UTC indicator)");
        assertTrue(value.startsWith("26"), "Year should be '26' for 2026");
    }

    // -------------------------------------------------------------------------
    // Composition — nested structures
    // -------------------------------------------------------------------------

    @Test
    void testNestedSequenceRoundtrips() {
        // Verify that composing encodeOid inside encodeSequence produces the correct
        // outer length. This is the pattern used for AlgorithmIdentifier.
        byte[] oid = DerEncoder.encodeOid("1.2.3");        // [0x06, 0x02, 0x2A, 0x03] — 4 bytes
        byte[] seq = DerEncoder.encodeSequence(oid);       // [0x30, 0x04, 0x06, 0x02, 0x2A, 0x03]

        assertEquals(0x30, seq[0] & 0xFF);  // SEQUENCE tag
        assertEquals(4, seq[1] & 0xFF);     // length = 4 (the oid TLV)
        assertEquals(6, seq.length);        // total = tag + length + 4 content bytes
    }

    @Test
    void testExplicitTagWrapsSequence() {
        // Verify that [0] EXPLICIT wrapping a SEQUENCE produces the correct outer tag and length.
        // This is the pattern used for the TBSCertificate version field.
        byte[] integerTwo = DerEncoder.encodeInteger(BigInteger.TWO);   // [0x02, 0x01, 0x02]
        byte[] tagged = DerEncoder.encodeExplicitTag(0, integerTwo);    // [0xA0, 0x03, 0x02, 0x01, 0x02]

        assertEquals(0xA0, tagged[0] & 0xFF);   // [0] EXPLICIT tag
        assertEquals(3, tagged[1] & 0xFF);      // length = 3 (the integer TLV)
        assertEquals(5, tagged.length);
    }
}
