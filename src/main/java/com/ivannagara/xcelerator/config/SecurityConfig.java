package com.ivannagara.xcelerator.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ivannagara.xcelerator.security.FirebaseAuthFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final FirebaseAuthFilter firebaseAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Disable CSRF protection, because currently we use stateless authentication
        // with Firebase Auth Tokens (token-based authentication)
        http.csrf(csrf -> csrf.disable());
        
        // Set session management to stateless,
        // building RESTful API without session management (no cookies)
        http.sessionManagement(session -> 
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        
        // Set permissions on endpoints
        http.authorizeHttpRequests(auth -> {
            // Public endpoints
            auth.requestMatchers("/api/public/**").permitAll();
            // Private endpoints
            auth.anyRequest().authenticated();
        });
        
        // Add Firebase JWT filter
        http.addFilterBefore(firebaseAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
