package com.example.authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


/**
 * User Management Configuration
 * <p>
 * Manages user authentication and storage.
 */
@Configuration
public class UserConfig {


    /**
     * SCENARIO 1: User Details Service
     * Manages users who can authenticate and get JWT tokens
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // Regular user with USER role
        UserDetails user = User.builder()
                .username("john.doe")
                .password(passwordEncoder().encode("userpass123"))
                .roles("USER")
                .build();

        // Admin user with both USER and ADMIN roles
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("adminpass123"))
                .roles("USER", "ADMIN")
                .authorities("ADMIN")
                .build();

        // Another regular user
        UserDetails alice = User.builder()
                .username("alice")
                .password(passwordEncoder().encode("alicepass123"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user, admin, alice);
    }


    /**
     * Password Encoder
     * <p>
     * Uses BCrypt algorithm for secure password hashing:
     * - One-way hash (cannot decrypt)
     * - Salted (each hash is unique)
     * - Adaptive (can increase cost over time)
     * */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
