package net.perseity;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Util {
    public static String b64Encode(byte[] byteArray) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new String(encoder.encode(byteArray), StandardCharsets.UTF_8);
    }

    public static byte[] b64Decode(String string) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(string.getBytes(StandardCharsets.UTF_8));
    }
}
