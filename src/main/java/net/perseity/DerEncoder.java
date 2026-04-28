package net.perseity;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * A minimal, standards-compliant ASN.1/DER encoder for the subset of types
 * required to construct an X.509 v3 certificate from scratch.
 *
 * <p>DER (Distinguished Encoding Rules) is a strict subset of BER (Basic Encoding Rules),
 * which is itself a binary encoding for ASN.1 (Abstract Syntax Notation One) data structures.
 * Every value is encoded as a <b>Tag-Length-Value (TLV)</b> triplet:
 * <ul>
 *   <li><b>Tag</b> — identifies the data type (1 byte in our subset)</li>
 *   <li><b>Length</b> — number of content bytes (1 or more bytes, see {@link #encodeLength})</li>
 *   <li><b>Value</b> — the raw content bytes</li>
 * </ul>
 *
 * <p>This class is package-private and entirely stateless: every method is a pure function
 * that accepts inputs and returns a new {@code byte[]}. It has no knowledge of certificates,
 * keys, or algorithms — it is a low-level serialisation utility only.
 *
 * <p><b>References:</b> ITU-T X.690 (ASN.1 BER/DER), RFC 5280 (X.509 certificates),
 * RFC 4055 (RSASSA-PSS AlgorithmIdentifier).
 */
class DerEncoder {

    // -------------------------------------------------------------------------
    // ASN.1 universal tag constants (X.690 Table 1)
    // -------------------------------------------------------------------------

    /**
     * INTEGER (primitive, universal 2)
     */
    private static final int TAG_INTEGER = 0x02;

    /**
     * BIT STRING (primitive, universal 3)
     */
    private static final int TAG_BIT_STRING = 0x03;

    /**
     * NULL (primitive, universal 5)
     */
    private static final int TAG_NULL = 0x05;

    /**
     * OBJECT IDENTIFIER (primitive, universal 6)
     */
    private static final int TAG_OID = 0x06;

    /**
     * UTCTime (primitive, universal 23)
     */
    private static final int TAG_UTC_TIME = 0x17;

    /**
     * SEQUENCE (constructed, universal 16).
     * The 0x30 byte is 0x20 (constructed bit) | 0x10 (universal tag 16).
     */
    private static final int TAG_SEQUENCE = 0x30;

    /**
     * Base tag byte for context-specific constructed types ({@code [n] EXPLICIT}).
     * The 0xA0 byte is 0x80 (context-specific class) | 0x20 (constructed bit).
     * The tag number {@code n} is OR'd in: {@code 0xA0 | n}.
     */
    private static final int TAG_CONTEXT_CONSTRUCTED = 0xA0;

    /**
     * Prevent instantiation — all methods are static.
     */
    private DerEncoder() {
    }

    // =========================================================================
    // Public encoding methods
    // =========================================================================

    /**
     * Encodes a {@link BigInteger} as a DER INTEGER (tag {@code 0x02}).
     *
     * <p>DER integers are signed, big-endian, and use the minimum number of bytes.
     * {@link BigInteger#toByteArray()} already produces this canonical form: it prepends
     * a {@code 0x00} sign byte when the high bit of the magnitude is set (to prevent the
     * value from being misread as negative), and strips unnecessary leading zeros.
     *
     * @param value The integer to encode. Must not be null.
     * @return Complete DER TLV bytes for the INTEGER.
     */
    static byte[] encodeInteger(BigInteger value) {
        return tlv(TAG_INTEGER, value.toByteArray());
    }

    /**
     * Encodes a dot-notation Object Identifier string as a DER OID (tag {@code 0x06}).
     *
     * <p>OID encoding rules per X.690 §8.19:
     * <ol>
     *   <li>The first two arc components {@code X.Y} are merged into a single byte:
     *       {@code 40 * X + Y}. (X is always 0, 1, or 2; Y is constrained accordingly.)</li>
     *   <li>Each subsequent arc component is encoded in base-128, most-significant group
     *       first, with the high bit ({@code 0x80}) set on every byte <em>except</em> the
     *       last — signalling that more bytes follow.</li>
     * </ol>
     *
     * <p>Example: OID {@code 1.2.840.113549.1.1.10} encodes as:
     * {@code 06 09 2a 86 48 86 f7 0d 01 01 0a}
     *
     * @param dotNotation OID in dot-notation, e.g. {@code "1.2.840.113549.1.1.10"}.
     * @return Complete DER TLV bytes for the OID.
     */
    static byte[] encodeOid(String dotNotation) {
        String[] parts = dotNotation.split("\\.");
        ByteArrayOutputStream content = new ByteArrayOutputStream();

        // First two arcs are combined: 40 * first + second
        content.write(40 * Integer.parseInt(parts[0]) + Integer.parseInt(parts[1]));

        // Each remaining arc is base-128 encoded (big-endian, high-bit continuation flag)
        for (int i = 2; i < parts.length; i++) {
            encodeBase128(Long.parseLong(parts[i]), content);
        }
        return tlv(TAG_OID, content.toByteArray());
    }

    /**
     * Encodes a byte array as a DER BIT STRING (tag {@code 0x03}) with zero unused bits.
     *
     * <p>A BIT STRING value is prefixed with one byte indicating how many bits of the
     * final content octet are unused (padding). For byte-aligned data — such as RSA
     * signatures and SubjectPublicKeyInfo — this is always {@code 0x00}.
     *
     * @param bytes The bit string content (byte-aligned). Must not be null.
     * @return Complete DER TLV bytes for the BIT STRING.
     */
    static byte[] encodeBitString(byte[] bytes) {
        // Prepend the "unused bits" byte (0x00 = fully used)
        byte[] content = new byte[bytes.length + 1];
        content[0] = 0x00;
        System.arraycopy(bytes, 0, content, 1, bytes.length);
        return tlv(TAG_BIT_STRING, content);
    }

    /**
     * Encodes a {@link Date} as a DER UTCTime (tag {@code 0x17}), formatted as
     * {@code YYMMDDhhmmssZ} in UTC.
     *
     * <p>UTCTime uses a two-digit year and is valid for dates from 1950 to 2049
     * (RFC 5280 §4.1.2.5). Years 00–49 represent 2000–2049; years 50–99 represent
     * 1950–1999. The trailing {@code Z} denotes UTC (Zulu) time.
     *
     * @param date The date to encode. Must not be null.
     * @return Complete DER TLV bytes for the UTCTime.
     */
    static byte[] encodeUtcTime(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return tlv(TAG_UTC_TIME, sdf.format(date).getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Encodes a DER NULL value (tag {@code 0x05}, length {@code 0x00}).
     *
     * <p>NULL is used as the {@code parameters} field in RSA {@code AlgorithmIdentifier}
     * structures where parameters are not needed (e.g. {@code sha256WithRSAEncryption}).
     * It is distinct from an <em>absent</em> parameters field, which is simply omitted.
     *
     * @return DER bytes {@code [0x05, 0x00]}.
     */
    static byte[] encodeNull() {
        return new byte[]{(byte) TAG_NULL, 0x00};
    }

    /**
     * Concatenates one or more pre-encoded DER values inside a DER SEQUENCE (tag {@code 0x30}).
     *
     * <p>A SEQUENCE is a constructed type: it contains an ordered list of other encoded
     * values. The caller is responsible for encoding each element first; this method simply
     * concatenates them and wraps them in the SEQUENCE TLV.
     *
     * <p>This pattern — encode elements, then wrap — mirrors how X.509 structures are built
     * bottom-up: inner structures are encoded first, then assembled into outer ones.
     *
     * @param elements Pre-encoded DER byte arrays to include in the SEQUENCE, in order.
     * @return Complete DER TLV bytes for the SEQUENCE.
     */
    static byte[] encodeSequence(byte[]... elements) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        for (byte[] element : elements) {
            content.write(element, 0, element.length);
        }
        return tlv(TAG_SEQUENCE, content.toByteArray());
    }

    /**
     * Wraps pre-encoded DER content in a context-specific {@code [n] EXPLICIT} tag.
     *
     * <p>An EXPLICIT outer tag adds a new TLV wrapper around the existing encoding, leaving
     * the original inner tag intact. This is used in X.509 for fields that need to be
     * unambiguously identified within a SEQUENCE, such as:
     * <ul>
     *   <li>{@code version [0] EXPLICIT INTEGER} in TBSCertificate</li>
     *   <li>{@code hashAlgorithm [0]} and {@code saltLength [2]} in RSASSA-PSS-params</li>
     * </ul>
     *
     * <p>The resulting tag byte is {@code 0xA0 | tagNumber}:
     * <ul>
     *   <li>Bits 7–6: {@code 10} = context-specific class</li>
     *   <li>Bit 5: {@code 1} = constructed</li>
     *   <li>Bits 4–0: the tag number</li>
     * </ul>
     *
     * @param tagNumber The context tag number (0–30).
     * @param content   The pre-encoded DER bytes to wrap.
     * @return Complete DER TLV bytes with the explicit context tag.
     */
    static byte[] encodeExplicitTag(int tagNumber, byte[] content) {
        return tlv(TAG_CONTEXT_CONSTRUCTED | tagNumber, content);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Assembles a complete DER TLV (Tag-Length-Value) triplet from a tag byte and content.
     *
     * <p>This is the fundamental building block of all DER encoding: every value is
     * represented as a tag identifying its type, a length field giving the number of
     * content bytes, and the content bytes themselves.
     *
     * @param tag     The ASN.1 tag byte (type identifier).
     * @param content The value bytes — already fully encoded content, without tag or length.
     * @return The complete {@code tag || length || content} byte array.
     */
    private static byte[] tlv(int tag, byte[] content) {
        byte[] length = encodeLength(content.length);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + length.length + content.length);
        out.write(tag);
        out.write(length, 0, length.length);
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    /**
     * Encodes a DER length field per X.690 §8.1.3.
     *
     * <p>DER uses two forms of length encoding:
     * <ul>
     *   <li><b>Short form</b> (0–127): a single byte whose value is the length.</li>
     *   <li><b>Long form</b> (128+): a first byte of {@code 0x80 | numBytes} followed by
     *       the length value in big-endian byte order. For example, length 256 encodes as
     *       {@code [0x82, 0x01, 0x00]}.</li>
     * </ul>
     *
     * @param length The number of content bytes (non-negative).
     * @return The DER-encoded length field (1–5 bytes for any 32-bit length).
     */
    private static byte[] encodeLength(int length) {
        if (length < 128) {
            // Short form: a single byte
            return new byte[]{(byte) length};
        }
        // Long form: count how many bytes are needed to hold the length value
        int numBytes = 0;
        int temp = length;
        while (temp > 0) {
            numBytes++;
            temp >>= 8;
        }
        byte[] encoded = new byte[1 + numBytes];
        encoded[0] = (byte) (0x80 | numBytes); // first byte: 0x80 + count of length bytes
        for (int i = numBytes; i > 0; i--) {
            encoded[i] = (byte) (length & 0xFF);
            length >>= 8;
        }
        return encoded;
    }

    /**
     * Encodes a single OID arc component value in base-128 (big-endian), writing bytes
     * directly to the provided output stream.
     *
     * <p>The value is split into 7-bit groups, most-significant first. The high bit
     * ({@code 0x80}) is set on every byte <em>except</em> the last, acting as a
     * continuation flag to indicate that more bytes follow.
     *
     * <p>Example: the arc value {@code 840} = {@code 0b110_1001000} splits into two
     * 7-bit groups: {@code 0b0000110} and {@code 0b1001000}, encoding as
     * {@code [0x86, 0x48]}.
     *
     * @param value The OID arc value (non-negative long).
     * @param out   The output stream to write the encoded bytes to.
     */
    private static void encodeBase128(long value, ByteArrayOutputStream out) {
        if (value == 0) {
            out.write(0);
            return;
        }
        // Count how many 7-bit groups are needed
        int numGroups = 0;
        long temp = value;
        while (temp > 0) {
            numGroups++;
            temp >>= 7;
        }
        // Write from most-significant to least-significant group
        for (int i = numGroups - 1; i >= 0; i--) {
            int group = (int) ((value >> (7 * i)) & 0x7F);
            out.write(i > 0 ? group | 0x80 : group); // set continuation bit on all but last
        }
    }
}
