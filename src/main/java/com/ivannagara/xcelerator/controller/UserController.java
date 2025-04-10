package com.ivannagara.xcelerator.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.ivannagara.xcelerator.model.Role;
import com.ivannagara.xcelerator.security.RequiredRole;
import com.ivannagara.xcelerator.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PutMapping;



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

            // userService.saveUserProfile(userRecord.getUid(), userData);

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

    @RequiredRole(Role.SUPER_ADMIN)
    @PostMapping("/admin/user")
    public ResponseEntity<?> superAdminCreateUser(@RequestBody Map<String, String> userData) {
        try {
            String email = userData.get("email");
            String password = userData.get("password");
            String roleStr = userData.get("role");

            if (email == null || password == null || roleStr == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Email, password, and role are required"));
            }

            // Getting the Role value from the String version
            Role role;

             try {
                role = Role.valueOf(roleStr.toUpperCase());
             } catch(IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid role. Must be one of: " + 
                    Arrays.stream(Role.values())
                        .map(Role::name)
                        .collect(Collectors.joining(", "))));
             }

             UserRecord userRecord = userService.createUser(email, password, role);

             return ResponseEntity.ok(Map.of(
                "message", "User created successfully",
                "userId", userRecord.getUid(),
                "role", role.name()));
        } catch(FirebaseAuthException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @RequiredRole(Role.ADMIN)
    @PutMapping("admin/user/{userId}/role")
    public ResponseEntity<?> adminUpdateUserRole(
        HttpServletRequest request,
        @PathVariable String userId,
        @RequestBody Map<String, String> roleData
    ) {
            String roleStr = roleData.get("role");
            if (roleStr == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Role is required"));
            }

            Role newRole;

            try {
                newRole = Role.valueOf(roleStr.toUpperCase());
            } catch(IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid role. Must be one of: " + 
                    Arrays.stream(Role.values())
                        .map(Role::name)
                        .collect(Collectors.joining(", "))));
            }

            Role currentRole = (Role) request.getAttribute("userRole");
            boolean isSuccess = userService.updateUserRole(userId, newRole, currentRole);

            if (isSuccess) {
                return ResponseEntity.ok(Map.of("message", "User role updated successfully"));
            } else {
                return ResponseEntity.status(403).body(Map.of(
                "error", "You don't have permission to assign this role"));
            }
    }

    @RequiredRole(Role.ADMIN)
    @GetMapping("/admin/users")
    public ResponseEntity<?> getAllUsers() {
        // This would be implemented to query all users from Firestore
        // For now, we'll return a placeholder
        return ResponseEntity.ok(Map.of("message", "This endpoint would return all users"));
    }

    @GetMapping("/roles")
    public ResponseEntity<?> getAvailableRoles() {
        List<String> roles = Arrays.stream(Role.values())
            .map(Role::name)
            .collect(Collectors.toList());
        
        return ResponseEntity.ok(Map.of("roles", roles));
    }
}
