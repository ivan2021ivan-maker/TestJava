package com.mkyong.crypto.encryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.*;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 *
 * SJCL 1.0.8
 *
 * dependencies:
 * compile group: 'org.bouncycastle', name: 'bcprov-jdk15on', version: '1.64'
 * compile group: 'org.json', name: 'json', version: '20190722'
 *
 * ref: https://blog.degering.name/posts/java-sjcl
 */
public class AesSJCL {
    // Simply prints out the decoded string.
    public static void main(String[] args) throws Exception {
        String password = "a";
        String plainText = "a";

        // encryption
        Map<String, Object> result = new AesSJCL().encrypt( password, plainText);
        String json =  new JSONObject(result).toString();
        System.out.printf("encrypted output:\n%s\n", json);

        System.out.printf("\njavascript testing code:\nsjcl.decrypt(\"%s\", '%s')\n", password, json);

        // decryption
        String decryptedText = new AesSJCL().decrypt(password, json);
        System.out.printf("\ndecrypted output: \n%s\n", decryptedText);
    }

    /**
     *
     * @param password  - password
     * @param encryptedText - {"cipher":"aes","mode":"ccm","ct":"r7U/Gp2r8LVNQR7kl5qLNd8=","salt":"VwSOS3jCn6M=","v":1,"ks":128,"iter":10000,"iv":"5OEwQPtHK2ej1mHwvOf57A==","adata":"","ts":128}
     * @return
     * @throws Exception
     */
    public String decrypt(String password, String encryptedText) throws Exception {
        Decoder d = Base64.getDecoder();

        // Decode the encoded JSON and create a JSON Object from it
        encryptedText="{\"cipher\":\"aes\",\"mode\":\"gcm\",\"ct\":\"qjUXXJwd7K1nSu7UspfLIw0=\",\"salt\":\"E1mjOgLqdqQ=\",\"v\":1,\"ks\":128,\"iter\":1000,\"iv\":\"MgyuJrfrhGzqms7DJka83w==\",\"adata\":\"\",\"ts\":128}";
        //               { "cipher" :"aes","   mode ":"gcm",   "ct" : "u4eMPARolG2NY3X2kih68P8=",  "salt ": "N4WHtbcFLSw=",  "v" :1, "ks" :128, "iter" :1000, "iv" : "O/3sKU56uWfxqYczXUJ/+A==",  "adata ":"",   "ts" :128}
        JSONObject j = new JSONObject(new String(encryptedText));

        // We need the salt, the IV and the cipher text;
        // all of them need to be Base64 decoded
        byte[] salt=d.decode(j.getString("salt"));
        byte[] iv=d.decode(j.getString("iv"));
        byte[] cipherText=d.decode(j.getString("ct"));

        // Also, we need the keySize and the iteration count
        int keySize = j.getInt("ks"), iterations = j.getInt("iter");

        // https://github.com/bitwiseshiftleft/sjcl/blob/master/core/ccm.js#L60
        int lol = 2;
        if (cipherText.length >= 1<<16) lol++;
        if (cipherText.length >= 1<<24) lol++;

        // Cut the IV to the appropriate length, which is 15 - L
        iv = Arrays.copyOf(iv, 15-lol);

        // Crypto stuff.
        // First, we need the secret AES key,
        // which is generated from password and salt
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(),
                salt, iterations, keySize);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Now it's time to decrypt.
        //Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding",
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding",
                new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

        // Return the final result after converting it to a string.
        return new String(cipher.doFinal(cipherText));
    }


    /**
     *
     * @param password
     * @param plainText
     * @return
     * @throws Exception
     */
    public Map<String, Object> encrypt(String password, String plainText) throws Exception {
        int iterations = 1000;  // default in SJCL
        int keySize = 128;

        // https://github.com/bitwiseshiftleft/sjcl/blob/master/core/convenience.js#L321
        // default salt bytes are 8 bytes
        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[8];
        sr.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        // https://github.com/bitwiseshiftleft/sjcl/blob/master/core/random.js#L87
        // default iv bytes are 16 bytes
        SecureRandom randomSecureRandom = SecureRandom.getInstanceStrong();
        byte[] iv = new byte[16];
        randomSecureRandom.nextBytes(iv);

        int ivl = iv.length;
        if (ivl < 7) {
            throw new RuntimeException("gcm: iv must be at least 7 bytes");
        }

        // compute the length of the length
        int ol=plainText.length();
        int L=2;
        for (; L<4 && ( ol >>> 8*L ) > 0; L++) {}
        if (L < 15 - ivl) { L = 15-ivl; }

        byte[] shortIV = Arrays.copyOf(iv, 15-L);

        // Now it's time to decrypt.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(shortIV));

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(UTF_8));

        Encoder encoder = Base64.getEncoder();

        Map<String, Object> map = new HashMap<>();
        map.put("iv", encoder.encodeToString(iv));
        map.put("iter", iterations);
        map.put("ks", keySize);
        map.put("salt", encoder.encodeToString(salt));
        map.put("ct", encoder.encodeToString(encryptedBytes));
        map.put("cipher", "aes");
        map.put("mode", "gcm");
        map.put("adata", "");
        map.put("v", 1);   // I don't know what it is.
        map.put("ts", 128);  // I don't know what it is.

        return map;
    }
}