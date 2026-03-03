package fixtures;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class Vulnerable {
    public void vulnerablePatterns() throws Exception {
        // RSA key generation (CRITICAL)
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);

        // EC key generation (CRITICAL)
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");

        // DSA (CRITICAL)
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA");

        // DH (CRITICAL)
        KeyPairGenerator dhKpg = KeyPairGenerator.getInstance("DH");

        // ECDH key agreement (CRITICAL)
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");

        // RSA signing (CRITICAL)
        Signature rsaSig = Signature.getInstance("SHA256withRSA");

        // RSA cipher (CRITICAL)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // MD5 (CRITICAL)
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // SHA-1 (CRITICAL)
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        // AES-128 (MODERATE)
        KeyGenerator aes128 = KeyGenerator.getInstance("AES");
        aes128.init(128);

        // 3DES (CRITICAL)
        Cipher des3 = Cipher.getInstance("DESede/CBC/PKCS5Padding");

        // HmacMD5 (CRITICAL)
        Mac hmacMd5 = Mac.getInstance("HmacMD5");
    }
}
