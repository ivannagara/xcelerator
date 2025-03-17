package com.ivannagara.xcelerator.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.ivannagara.xcelerator.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/public/health")
    public ResponseEntity<Map<String, String>> checkHealth() {
        Map<String, String> response = new HashMap<String, String>();
        response.put("status", "UP");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/public/register")
    public ResponseEntity<?> registerUser(@RequestBody Map<String, String> registrationData) {
        try {
            String email = registrationData.get("email");
            String password = registrationData.get("password");

            if (email == null || password == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Email and password are required"));
            }

            UserRecord userRecord = userService.createUser(email, password);

            Map<String, Object> userData = new HashMap<String, Object>();
            userData.put("email", email);
            userData.put("createdAt", System.currentTimeMillis());

            userService.saveUserProfile(userRecord.getUid(), userData);

            Map<String, String> response = new HashMap<String, String>();
            response.put("message", "Successfully registered user");
            response.put("userId", userRecord.getUid());

            return ResponseEntity.ok(response);
        } catch(FirebaseAuthException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/profile/{userId}")
    public ResponseEntity<?> getUserProfile(@PathVariable String userId) {
        try {
            UserRecord userRecord = userService.getUserById(userId);
            Map<String, Object> userProfile = userService.getUserProfileSafe(userId);
            
            Map<String, Object> response = new HashMap<>();
            response.put("uid", userRecord.getUid());
            response.put("email", userRecord.getEmail());
            response.put("displayName", userRecord.getDisplayName());
            response.put("profile", userProfile);
            
            return ResponseEntity.ok(response);
        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }
    }

    @PostMapping("/profile/{userId}")
    public ResponseEntity<?> updateUserProfile(
        HttpServletRequest request,
        @PathVariable String userId,
        @RequestBody Map<String, Object> profileData
        ) {
            userService.saveUserProfile(userId, profileData);
            
            return ResponseEntity.ok(Map.of("message", "Profile updated successfully"));
    }
}
