package com.secureshare.app;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoUtil {
    private static final int ITERATIONS = 180000;
    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int len) throws Exception {
        int hLen = 32;
        int blocks = (len + hLen - 1) / hLen;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 1; i <= blocks; i++) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(password, "HmacSHA256"));
            mac.update(salt);
            mac.update(ByteBuffer.allocate(4).putInt(i).array());
            byte[] u = mac.doFinal();
            byte[] t = u.clone();
            for (int j = 1; j < iterations; j++) {
                mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(password, "HmacSHA256"));
                u = mac.doFinal(u);
                for (int k = 0; k < t.length; k++) t[k] ^= u[k];
            }
            out.write(t);
        }
        byte[] all = out.toByteArray();
        byte[] key = new byte[len];
        System.arraycopy(all, 0, key, 0, len);
        return key;
    }

    public static byte[] encrypt(String passphrase, byte[] plain) throws Exception {
        byte[] salt = new byte[16]; RNG.nextBytes(salt);
        byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
        byte[] key = pbkdf2(passphrase.getBytes(StandardCharsets.UTF_8), salt, ITERATIONS, 32);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD("SecureShare-v1".getBytes(StandardCharsets.UTF_8));
        byte[] sealed = c.doFinal(plain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'S','S','E','1'}); out.write(salt); out.write(nonce.length); out.write(nonce); out.write(sealed);
        return out.toByteArray();
    }

    public static byte[] decrypt(String passphrase, byte[] enc) throws Exception {
        if (enc.length < 33 || enc[0] != 'S' || enc[1] != 'S' || enc[2] != 'E' || enc[3] != '1') throw new Exception("Invalid SecureShare payload");
        byte[] salt = new byte[16]; System.arraycopy(enc, 4, salt, 0, 16);
        int n = enc[20] & 0xff;
        byte[] nonce = new byte[n]; System.arraycopy(enc, 21, nonce, 0, n);
        byte[] ct = new byte[enc.length - 21 - n]; System.arraycopy(enc, 21 + n, ct, 0, ct.length);
        byte[] key = pbkdf2(passphrase.getBytes(StandardCharsets.UTF_8), salt, ITERATIONS, 32);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD("SecureShare-v1".getBytes(StandardCharsets.UTF_8));
        return c.doFinal(ct);
    }

    public static String sha256(byte[] data) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder(); for (byte b : d) sb.append(String.format("%02x", b)); return sb.toString();
    }
}
