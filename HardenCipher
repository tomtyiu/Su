import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class EncryptionExample {
    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 10000;
    private static final int SALT_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        String passphrase = "MySecretPassphrase";
        String plaintext = "This is the message to be encrypted.";

        // Generate a random salt
        byte[] salt = generateSalt();

        // Derive AES key from passphrase and salt
        SecretKey secretKey = deriveAESKey(passphrase, salt);

        // Encrypt the plaintext
        byte[] ciphertext = encrypt(plaintext, secretKey);

        // Decrypt the ciphertext
        String decryptedText = decrypt(ciphertext, secretKey);

        // Print the results
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("Decrypted text: " + decryptedText);
    }

    private static byte[] generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static SecretKey deriveAESKey(String passphrase, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec);
    }

    private static byte[] encrypt(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    private static String decrypt(byte[] ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
