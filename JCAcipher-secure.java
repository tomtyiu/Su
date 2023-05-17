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
            throw new RuntimeException("No console available. Please run this program from a command-line terminal.");
        }

        char[] passphraseChars = null;
        try {
            passphraseChars = console.readPassword("Enter passphrase: ");
            String passphrase = sanitizeInput(new String(passphraseChars));
            Arrays.fill(passphraseChars, ' '); // Clear the passphrase from memory

            String plaintext = console.readLine("Enter the message to be encrypted: ");
            plaintext = sanitizeInput(plaintext);

            byte[] salt = generateSalt();
            SecretKey secretKey = deriveAESKey(passphrase, salt);

            byte[] nonce = generateNonce();
            byte[] ciphertext = encrypt(plaintext, secretKey, nonce);
            String decryptedText = decrypt(ciphertext, secretKey, nonce);

            System.out.println("Plaintext: " + encode(plaintext));
            System.out.println("Ciphertext: " + encode(ciphertext));
            System.out.println("Decrypted text: " + encode(decryptedText));
        } finally {
            if (passphraseChars != null) {
                Arrays.fill(passphraseChars, ' '); // Clear the passphrase from memory
            }
        }
    }

    /**
     * Sanitizes the input string to prevent SQL injection and cross-site scripting attacks.
     *
     * @param input The input string to sanitize.
     * @return The sanitized input string.
     */
    private static String sanitizeInput(String input) {
        return input.replaceAll("[<>\"']", "");
    }

    /**
     * Encodes the input string using Base64 encoding.
     *
     * @param input The input string to encode.
     * @return The encoded string.
     */
    private static String encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generates a random salt using a secure random number generator.
     *
     * @return The generated salt.
     */
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(salt);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate salt. SecureRandom algorithm not available.", e);
        }
        return salt;
    }

    /**
     * Generates a random nonce using a secure random number generator.
     *
     * @return The generated nonce.
     */
    private static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(nonce);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate nonce. SecureRandom algorithm not available.", e);
        }
        return nonce;
    }

    /**
     * Derives an AES key from the given passphrase and salt using PBKDF2 key derivation.
     *
     * @param passphrase The passphrase to derive the key from.
     * @param salt       The salt used for key derivation.
     * @return The derived AES key.
     */
    private static SecretKey deriveAESKey(String passphrase, byte[] salt)
            throws InvalidKeySpecException {
        try {
            PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, ITERATIONS, KEY_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), ALGORITHM.split("/")[0]);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to derive AES key. PBKDF2 algorithm not available.", e);
        }
    }

    /**
     * Encrypts the plaintext using the given secret key and nonce.
     *
     * @param plaintext  The plaintext to encrypt.
     * @param secretKey  The secret key used for encryption.
     * @param nonce      The nonce used for encryption.
     * @return The encrypted ciphertext.
     */
    private static byte[] encrypt(String plaintext, SecretKey secretKey, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypts the ciphertext using the given secret key and nonce.
     *
     * @param ciphertext The ciphertext to decrypt.
     * @param secretKey  The secret key used for decryption.
     * @param nonce      The nonce used for decryption.
     * @return The decrypted plaintext.
     */
    private static String decrypt(byte[] ciphertext, SecretKey secretKey, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
