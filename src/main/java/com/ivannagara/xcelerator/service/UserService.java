package com.ivannagara.xcelerator.service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.springframework.stereotype.Service;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.auth.UserRecord.CreateRequest;
import com.ivannagara.xcelerator.model.Role;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

        private final FirebaseAuth firebaseAuth;
        private final Firestore firestore;

        private static final String USERS_COLLECTION = "users";

        public UserRecord createUser(String email, String password, Role role) throws FirebaseAuthException {
            CreateRequest request = new CreateRequest()
                .setEmail(email)
                .setPassword(password)
                .setEmailVerified(false);

            UserRecord userRecord = firebaseAuth.createUser(request);

            Map<String, Object> userData = new HashMap<>();
            userData.put("email", email);
            userData.put("uid", userRecord.getUid());
            userData.put("role", role.toString());
            
            saveUserProfile(userRecord.getUid(), userData);
    
            return userRecord;
        }

        public UserRecord createUser(String email, String password) throws FirebaseAuthException {
            return createUser(email, password, Role.STAFF);
        }

        public UserRecord getUserById(String uid) throws FirebaseAuthException {
            return firebaseAuth.getUser(uid);
        }

        public Map<String, Object> getUserProfileFromFirestore(String uid) throws InterruptedException, ExecutionException {
                DocumentReference docRef = firestore.collection(USERS_COLLECTION).document(uid);
                ApiFuture<DocumentSnapshot> future = docRef.get();
                DocumentSnapshot document = future.get();

                if (document.exists()) {
                    return document.getData();
                } else {
                    log.info("No user profile for UID: {}", uid);
                    return new HashMap<>();
                }
        }

        public void saveUserProfile(String uid, Map<String, Object> userData) {
            DocumentReference docRef = firestore.collection(USERS_COLLECTION).document(uid);
            docRef.set(userData).addListener(() -> log.info("User profile saved for uid: {}", uid), Runnable::run);
        }

        public Map<String, Object> getUserProfileSafe(String uid) {
            try {
                return getUserProfileFromFirestore(uid);
            } catch(InterruptedException e) {
                log.error("Thread interrupted while getting user profile", e);
                Thread.currentThread().interrupt();
                return new HashMap<>();
            } catch(ExecutionException e) {
                log.error("Error executing Firestore query", e);
                return new HashMap<>();
            }
        }

        public Role getUserRole(String uid) {
            try {
                Map<String, Object> profile = getUserProfileFromFirestore(uid);
                if (profile.containsKey("role")) {
                    String roleStr = (String) profile.get("role");
                    return Role.valueOf(roleStr.toUpperCase());
                }
            } catch(Exception e) {
                log.error("Error getting user role", e);
            }
            return Role.STAFF;
        }

        /**
         *  Only SUPER_ADMIN can set SUPER_ADMIN role; 
         *  ADMIN can only set STAFF role
         */
        public boolean updateUserRole(String uid, Role newRole, Role currentUserRole) {
            if (newRole == Role.SUPER_ADMIN && currentUserRole != Role.SUPER_ADMIN) {
                return false;
            }

            if (currentUserRole == Role.ADMIN && newRole != Role.STAFF) {
                return false;
            }

            try {
                Map<String, Object> updates = new HashMap<>();
                updates.put("role", newRole.name());
                
                DocumentReference docRef = firestore.collection(USERS_COLLECTION).document(uid);
                docRef.update(updates);
                log.info("Updated role for user {} to {}", uid, newRole);
                return true;
            } catch (Exception e) {
                log.error("Failed to update user role", e);
                return false;
            }
        }
}
