package com.mkyong.crypto.encryptor;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

public class SJCLDecryptTest {
	
	public static final Charset UTF_8 = StandardCharsets.UTF_8;
	
	
    // Simply prints out the decoded string.
    public static void main(String[] args) throws Exception {
    	//GCM Mode
    	//System.out.println(new SJCLDecryptTest().decrypt("eyJtb2RlIjoiZ2NtIiwiY2lwaGVyIjoiYWVzIiwiY3QiOiJNUVdCMzlobnVsSnp2TTRQN0VmcDV6WHQrOVVVR0FUZXBuL25scmxiIiwic2FsdCI6InZtc09mVWVKVERjPSIsInYiOjEsImtzIjoxMjgsIml0ZXIiOjEwMDAsIml2IjoiYTQzL1cwZ3BCUjdvRmc2U1BFZmVmdz09IiwiYWRhdGEiOiIiLCJ0cyI6MTI4fQ==", "password"));
    	//https://www.base64decode.org/  
    	//System.out.println(new SJCLDecryptTest().decrypt("eyJpdiI6Ik53ZS9CWTQ5M1QvRjYxTnVZemMxQmc9PSIsCiJ2IjoxLAoiaXRlciI6MTAwMCwKImtzIjoxMjgsCiJ0cyI6MTI4LAoibW9kZSI6ImdjbSIsCiJhZGF0YSI6IiIsCiJjaXBoZXIiOiJhZXMiLAoic2FsdCI6IlI1QWlaVS9PWWdrPSIsCiJjdCI6IndFM1VGTFdnVGhyL1kvL2RXcEhZRkYxTVhUeEVRbXc9In0=", "password"));
    	//System.out.println(new SJCLDecryptTest().decrypt("eyJpdiI6IlhsUTBocXVyTEp0OWkwZFlxZFhhQ3c9PSIsCiJ2IjoxLAoiaXRlciI6MTAwMCwKImtzIjoxMjgsCiJ0cyI6MTI4LAoibW9kZSI6ImdjbSIsCiJhZGF0YSI6IiIsCiJjaXBoZXIiOiJhZXMiLAoic2FsdCI6IlI1QWlaVS9PWWdrPSIsCiJjdCI6IjZlZWZSdXR4enZLQ2Vvb0Vvc1M3ZXR3aDh4YVhPeEZkWGk4Rk1za0o0eEZjdmppMmp2UDh2S25PYmZ4M2hRREtaWCtjejR1OEhncz0ifQ==", "password"));
    	System.out.println(new SJCLDecryptTest().decrypt("eyJpdiI6IllyZGQ0VElqUXpIZkJRZXBRVzFNTkE9PSIsCiJ2IjoxLAoiaXRlciI6MTAwMCwKImtzIjoxMjgsCiJ0cyI6MTI4LAoibW9kZSI6ImdjbSIsCiJhZGF0YSI6IiIsCiJjaXBoZXIiOiJhZXMiLAoic2FsdCI6Ilg0Ukg3VUxDUTlFPSIsCiJjdCI6Ind0YW51VFNwQWVLQTZJa1RlMG1CU2pWRUZJOEFmaHhLIn0=", "zaq12wsx"));
    	//System.out.println(new SJCLDecryptTest().decrypt("eyJpdiI6IllhNCtUNGVMYU1MQ0oyQUhuSTJZTnc9PSIsCiJ2IjoxLAoiaXRlciI6MTAwMCwKImtzIjoxMjgsCiJ0cyI6MTI4LAoibW9kZSI6ImdjbSIsCiJhZGF0YSI6IiIsCiJjaXBoZXIiOiJhZXMiLAoic2FsdCI6Ikd2YTg3UUNxY2kwPSIsCiJjdCI6ImcwZ3RMM29jMUlXcy9KeWhsR1lubDVPLzZqN3hSZz09In0=", "password"));
    	//CCM Mode
    	//System.out.println(new SJCLDecryptTest().decrypt("eyJtb2RlIjoiY2NtIiwiY2lwaGVyIjoiYWVzIiwiY3QiOiJNQVZjZ1liL0ErN2dwR1RPYWR6Ri9UdFY1OStIRFE9PSIsInNhbHQiOiJ2bXNPZlVlSlREYz0iLCJ2IjoxLCJrcyI6MTI4LCJpdGVyIjoxMDAwLCJpdiI6ImJWemFnc3JMQjJselp3QllVNWhjMUE9PSIsImFkYXRhIjoiIiwidHMiOjY0fQ==", "password"));
    	
/*    	
        System.out.println(new SJCLDecryptTest().decrypt(
                "eyJpdiI6IjVvbHZ2bmR5Mm9kMjNqVGh2ZUZSeXc9PSIsDQoidiI6MSwNC"
                        + "iJpdGVyIjoxMDAwLA0KImtzIjoxMjgsDQoidHMiOjY0LA0KIm1vZGUiOi"
                        + "JjY20iLA0KImFkYXRhIjoiIiwNCiJjaXBoZXIiOiJhZXMiLA0KInNhbHQ"
                        + "iOiJwYXJZdjlFMUxZTT0iLA0KImN0IjoiS2RNZHBRbmZiWUFuUnRyNktj"
                        + "cjU2NkxJc1R6WC93PT0ifQ==",
                "password"));
*/
    }

    // We need a Base64 decoder, so lets get one (and reuse it)
    private Decoder d = Base64.getDecoder();

    // The function takes the Base64 encoded JSON object and the password as arguments
    private String decrypt(String encodedJSON, String password) throws Exception {
        // Decode the encoded JSON and create a JSON Object from it
        JSONObject j = new JSONObject(new String(d.decode(encodedJSON)));

        // We need the salt, the IV and the cipher text;
        // all of them need to be Base64 decoded
        byte[] salt=d.decode(j.getString("salt"));
        byte[] iv=d.decode(j.getString("iv"));
        byte[] cipherText=d.decode(j.getString("ct"));

        // Also, we need the keySize and the iteration count
        int keySize = j.getInt("ks"), iterations = j.getInt("iter");

        // Now, SJCL doesn't use the whole IV in CCM mode;
        // the length L depends on the length of the cipher text and is
        // either 2 (< 32768 bit length),
        // 3 (< 8388608 bit length) or
        // 4 (everything larger).
        // c.f. https://github.com/bitwiseshiftleft/sjcl/blob/master/core/ccm.js#L60
        //CCM Mode
        //int lol = 2;
        
        //GCM Mode
        //int lol = 4;
        
        //if (cipherText.length >= 1<<16) lol++;
        //if (cipherText.length >= 1<<24) lol++;

        // Cut the IV to the appropriate length, which is 15 - L
        //iv = Arrays.copyOf(iv, 15-lol);

        // Crypto stuff.
        // First, we need the secret AES key,
        // which is generated from password and salt
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        // Now it's time to decrypt.
        //GCM Mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(128, iv));
        byte[] encryptedText = cipher.doFinal(cipherText);
        return new String(encryptedText, UTF_8);
        //CCM Mode
        //Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", new BouncyCastleProvider());
        //cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

        // Return the final result after converting it to a string.
        //return new String(cipher.doFinal(cipherText));      
    }
}