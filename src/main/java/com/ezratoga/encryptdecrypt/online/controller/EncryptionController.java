package com.ezratoga.encryptdecrypt.online.controller;

import org.springframework.web.bind.annotation.*;

import com.ezratoga.encryptdecrypt.online.service.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class EncryptionController {

    private final EncryptionService encryptionService;

    public EncryptionController(EncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @PostMapping("/encrypt")
    public Map<String, String> encrypt(@RequestBody Map<String, String> request) {
        try {
            String text = request.get("text");
            String key = request.get("key");

            if (text == null || key == null) {
                return Map.of("error", "Both 'text' and 'key' are required.");
            }

            String encryptedData = encryptionService.encrypt(text, key);
            return Map.of("encrypted", encryptedData);
        } catch (Exception e) {
            return Map.of("error", "Encryption failed: " + e.getMessage());
        }
    }

    @PostMapping("/decrypt")
    public Map<String, String> decrypt(@RequestBody Map<String, String> request) {
        try {
            String encryptedText = request.get("text");
            String key = request.get("key");

            if (encryptedText == null || key == null) {
                return Map.of("error", "Both 'text' and 'key' are required.");
            }

            String decryptedData = encryptionService.decrypt(encryptedText, key);
            return Map.of("decrypted", decryptedData);
        } catch (Exception e) {
            return Map.of("error", "Decryption failed: " + e.getMessage());
        }
    }
}
