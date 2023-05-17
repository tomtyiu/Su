import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class EncryptionExample {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 100_000;
    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        Console console = System.console();
        if (console == null) {
            System.err.println("No console available. Please run this program from a command-line terminal.");
            System.exit(1);
        }

        // Read passphrase securely
        char[] passphraseChars = console.readPassword("Enter passphrase: ");
        String passphrase = sanitizeInput(new String(passphraseChars));
        Arrays.fill(passphraseChars, ' '); // Clear the passphrase from memory

        // Read plaintext message
        String plaintext = console.readLine("Enter the message to be encrypted: ");
        plaintext = sanitizeInput(plaintext);

        // Generate salt and derive secret key
        byte[] salt = generateSalt();
        SecretKey secretKey = deriveAESKey(passphrase, salt);

        // Generate nonce and perform encryption
        byte[] nonce = generateNonce();
        byte[] ciphertext = encrypt(plaintext, secretKey, nonce);
        String decryptedText = decrypt(ciphertext, secretKey, nonce);

        // Display results
        System.out.println("Plaintext: " + encode(plaintext));
        System.out.println("Ciphertext: " + encode(ciphertext));
        System.out.println("Decrypted text: " + encode(decryptedText));
    }

    // Sanitize input to prevent potential vulnerabilities
    private static String sanitizeInput(String input) {
        return input.replaceAll("[<>\"']", "");
    }

    // Base64 encode the input string
    private static String encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    // Generate a random salt
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        secureRandom.nextBytes(salt);
        return salt;
    }

    // Generate a random nonce
    private static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    // Derive AES key from passphrase and salt using PBKDF2
    private static SecretKey deriveAESKey(String passphrase, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM.split("/")[0]);
    }

    // Encrypt the plaintext using AES-GCM algorithm
    private static byte[] encrypt(String plaintext, SecretKey secretKey, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    // Decrypt the ciphertext using AES-GCM algorithm
    private static String decrypt(byte[] ciphertext, SecretKey secretKey, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
