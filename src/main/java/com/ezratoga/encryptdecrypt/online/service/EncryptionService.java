package com.ezratoga.encryptdecrypt.online.service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Service;

@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16; // AES-CBC requires a 16-byte IV

    /**
     * Generates a 256-bit AES key from the user-provided key.
     */
    private SecretKey getKeyFromPassword(String key) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(key.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypts the input text using AES-256-CBC with a random IV.
     */
    public String encrypt(String data, String key) throws Exception {
        SecretKey secretKey = getKeyFromPassword(key);

        // Generate a random IV
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // Combine IV and encrypted text and encode in Base64
        byte[] combined = new byte[IV_SIZE + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, IV_SIZE);
        System.arraycopy(encryptedBytes, 0, combined, IV_SIZE, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypts the encrypted text using AES-256-CBC.
     */
    public String decrypt(String encryptedData, String key) throws Exception {
        SecretKey secretKey = getKeyFromPassword(key);

        byte[] combined = Base64.getDecoder().decode(encryptedData);

        // Extract IV from the first 16 bytes
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(combined, 0, iv, 0, IV_SIZE);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Extract encrypted text
        byte[] encryptedBytes = new byte[combined.length - IV_SIZE];
        System.arraycopy(combined, IV_SIZE, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}