package com.ivannagara.xcelerator.security;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.ivannagara.xcelerator.model.Role;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

@Component
@RequiredArgsConstructor
@Slf4j
public class FirebaseAuthFilter extends OncePerRequestFilter {

    private final FirebaseAuth firebaseAuth;
    private final Firestore firestore;
    
    // Paths that don't require authentication
    private final List<String> publicPaths = new ArrayList<>(List.of("/api/public/**"));

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String path = request.getRequestURI();
        log.debug("Processing request for path: {}", path);
        
        // Skip authentication for public paths
        if (isPublicPath(path)) {
            log.debug("Public path detected, skipping authentication: {}", path);
            filterChain.doFilter(request, response);
            return;
        }
        
        String authorizationHeader = request.getHeader("Authorization");
        
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            log.debug("Missing or invalid Authorization header");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Missing or invalid Authorization header");
            return;
        }
        
        String token = authorizationHeader.substring(7);
        
        try {
            FirebaseToken decodedToken = firebaseAuth.verifyIdToken(token);
            String uid = decodedToken.getUid();
            
            // Can set user details in request attributes for controllers to access
            request.setAttribute("userId", uid);
            request.setAttribute("userEmail", decodedToken.getEmail());

            // Set basic user details in request attributes
            setUserRole(request, uid);
            
            filterChain.doFilter(request, response);
        } catch (FirebaseAuthException e) {
            log.error("Firebase Authentication failed", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid token: " + e.getMessage());
        }
    }

    /**
     * Get the current user's role from the database
     * and apply it to the request body as an attribute
     */
    private void setUserRole(HttpServletRequest request, String uid) {
        try {
            DocumentReference userRef = firestore.collection("users").document(uid);
            ApiFuture<DocumentSnapshot> future = userRef.get();
            DocumentSnapshot document = future.get();

            if (document.exists() && document.contains("role")) {
                String roleStr = document.getString("role");
                try {
                    Role role = Role.valueOf(roleStr.toUpperCase());
                    request.setAttribute("userRole", role);
                    log.debug("Set user role: {}", role);
                } catch(IllegalArgumentException e) {
                    log.warn("Invalid role value in database: {}", roleStr);
                    // Default the role into the lowest permission level
                    request.setAttribute("userRole", Role.STAFF);
                }
            } else {
                log.debug("No role found for user: {}, defaulting to STAFF", uid);
                request.setAttribute("userRole", Role.STAFF);
            }

        } catch(InterruptedException e) {
            log.error("Thread interrupted while fetching user role", e);
            Thread.currentThread().interrupt();
            request.setAttribute("userRole", Role.STAFF);
        } catch(ExecutionException e) {
            log.error("Error executing Firestore query for user role", e);
            request.setAttribute("userRole", Role.STAFF);
        }
    }
    
    private boolean isPublicPath(String path) {
        return publicPaths.stream().anyMatch(pattern -> {
            if (pattern.endsWith("/**")) {
                String prefix = pattern.substring(0, pattern.length() - 3);
                return path.startsWith(prefix);
            }
            return path.equals(pattern);
        });
    }
}