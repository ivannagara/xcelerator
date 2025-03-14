package com.ivannagara.xcelerator.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.ivannagara.xcelerator.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(HttpServletRequest request) throws FirebaseAuthException {
        String userId = (String) request.getAttribute("userId");

        try {
            UserRecord userRecord = userService.getUserById(userId);
            Map<String, Object> userProfile = userService.getUserProfileSafe(userId);

            Map<String, Object> response = new HashMap<>();
            response.put("uid", userRecord.getUid());
            response.put("email", userRecord.getEmail());
            response.put("displayName", userRecord.getDisplayName());
            response.put("profile", userProfile);

            return ResponseEntity.ok(response);
        } catch(FirebaseAuthException e) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }
    }

    @PostMapping("/profile")
    public ResponseEntity<?> updateUserProfile(
        HttpServletRequest request,
        @RequestBody Map<String, Object> profileData
        ) {
            String userId = (String) request.getAttribute("userId");

            userService.saveUserProfile(userId, profileData);
            
            return ResponseEntity.ok(Map.of("message", "Profile updated successfully"));
    }
}
