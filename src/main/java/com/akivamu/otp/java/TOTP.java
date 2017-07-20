package com.akivamu.otp.java;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

public class TOTP {
    private static final int DEFAULT_DIGITS = 6;
    private static final int DEFAULT_STEP = 30;
    private static final Crypto DEFAULT_CRYPTO = Crypto.SHA1;
    private static final Encoding DEFAULT_ENCODING = Encoding.BASE32;

    private static int digits = DEFAULT_DIGITS;
    private static int step = DEFAULT_STEP;
    private static Crypto crypto = DEFAULT_CRYPTO;
    private static Encoding encoding = DEFAULT_ENCODING;


    private TOTP() {
    }

    public static void setDigits(int digits) {
        TOTP.digits = digits;
    }

    public static void setStep(int step) {
        TOTP.step = step;
    }

    public static void setCrypto(Crypto crypto) {
        TOTP.crypto = crypto;
    }

    public static void setEncoding(Encoding encoding) throws UnsupportedEncodingException {
        // TODO
        if (Encoding.ASCII.equals(encoding) || Encoding.HEX.equals(encoding))
            throw new UnsupportedEncodingException("Unsupported " + encoding);

        TOTP.encoding = encoding;
    }

    public static String generateToken(String secret) {
        return generateToken(secret, System.currentTimeMillis());
    }

    public static String generateToken(String secret, long time) {
        secret = processString(secret);

        byte[] decodedSecret = null;
        switch (encoding) {
            case HEX:
            case ASCII:
                return null;
            case BASE32:
                Base32 base32 = new Base32();
                decodedSecret = base32.decode(secret);
                break;
            case BASE64:
                Base64 base64 = new Base64();
                decodedSecret = base64.decode(secret);
                break;
        }
        return generateToken(decodedSecret, time);
    }

    public static String generateToken(byte[] secret) {
        return generateToken(secret, System.currentTimeMillis());
    }

    // Full option
    public static String generateToken(byte[] secret, long time) {
        // Interval
        long interval = time / 1000 / step;
        byte[] hash = getMacHash(secret, interval, crypto);

        // Calculate
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        return String.valueOf(binary % getDigitPower(digits));
    }

    private static byte[] getMacHash(byte[] secret, long interval, Crypto crypto) {
        byte[] msg = ByteBuffer.allocate(8).putLong(interval).array();
        return hmacSha(crypto, secret, msg);
    }

    private static byte[] hmacSha(Crypto crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto.toString());
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    private static long getDigitPower(int digits) {
        return (long) Math.pow(10, digits);
    }

    private static String processString(String input) {
        return input.toUpperCase().replaceAll("\\s+", "");
    }

    public enum Encoding {
        ASCII,
        HEX,
        BASE32,
        BASE64
    }

    public enum Crypto {
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA512("HmacSHA512");

        private String value;

        Crypto(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return value;
        }
    }
}