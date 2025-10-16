package com.example.authorization_server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * JWT Configuration
 * <p>
 * Manages cryptographic keys for JWT token signing and verification.
 * <p>
 * Key Concepts:
 * - RSA Asymmetric Encryption
 * - Private Key: Signs tokens (kept secret on auth server)
 * - Public Key: Verifies tokens (shared publicly via /oauth2/jwks)
 * Current Implementation: In-Memory Key Generation
 * ⚠️ WARNING: Keys regenerated on every server restart!
 * - All existing tokens become invalid after restart
 * - Users must re-authenticate
 * <p>
 * Production Solution: Persistent Key Storage
 * - Load keys from file system
 * - Store in database
 * - Use Hardware Security Module (HSM)
 * - Implement key rotation strategy
 */
@Configuration
public class JwtConfig {

    /**
     * JWK Source (JSON Web Key Source)
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);

    }


    /**
     * Generate RSA Key Pair
     * <p>
     * Creates a 2048-bit RSA key pair for JWT signing.
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        return keyPair;
    }


    /**
     * JWT Decoder
     * <p>
     * Decodes and validates JWT tokens.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

}
