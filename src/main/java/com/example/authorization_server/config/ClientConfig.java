package com.example.authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * OAuth2 Client Configuration
 * <p>
 * Registers OAuth2 clients (applications) that can request tokens.
 * <p>
 * Registered Clients:
 * 1. user-client     - For password grant (deprecated, for demo only)
 * 2. app-client      - For client credentials (machine-to-machine)
 * 3. web-app-client  - For authorization code (user login via browser)
 * 4. public-client   - Flexible client for testing
 * <p>
 * Current Implementation: In-Memory Storage
 * Production Alternative: Database Storage (JPA + ClientRepository)
 */
@Configuration
public class ClientConfig {


    private final PasswordEncoder passwordEncoder;

    public ClientConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    /**
     * Registered Client Repository
     * Defines OAuth2 clients (applications) that can request tokens
     * CLIENT 1: For users to get tokens (Password Grant)
     * CLIENT 2: For applications to get tokens (Client Credentials Grant)
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        /**
         * Client 1: User Client (Password Grant)
         *
         * Grant Type: PASSWORD (deprecated in OAuth 2.1)
         * Use Case: Direct user authentication (username/password)
         * Security: Only for trusted first-party applications
         *
         * ⚠️ WARNING: Password grant is deprecated!
         * Use Authorization Code Flow instead for better security.
         */
        RegisteredClient userClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("user-client")
                .clientSecret(passwordEncoder.encode("user-client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                // Password Grant: User provides username/password directly
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                // Refresh Token: Allow users to refresh their tokens
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                // Scopes available for users
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .scope("write")

                // Token configuration for users
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))  // 30 min access token
                        .refreshTokenTimeToLive(Duration.ofHours(8))    // 8 hour refresh token
                        .reuseRefreshTokens(false)                       // Issue new refresh token on refresh
                        .build())

                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)  // No consent screen needed
                        .build())
                .build();


        /**
         * Client 2: Application Client (Client Credentials)
         *
         * Grant Type: CLIENT_CREDENTIALS
         * Use Case: Machine-to-machine communication (no user involved)
         * Examples: Microservices, background jobs, cron tasks
         *
         * Characteristics:
         * - No user authentication required
         * - No refresh token (request new token when expired)
         * - Application-level permissions only
         */
        RegisteredClient appClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("app-client")
                .clientSecret(passwordEncoder.encode("app-client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                // Client Credentials: Application authenticates with its own credentials
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

                // Scopes available for applications (typically more limited)
                .scope("api.read")
                .scope("api.write")
                .scope("service.access")

                // Token configuration for applications
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))  // 1 hour access token
                        // No refresh token for client credentials
                        .build())

                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        /**
         * Client 3: Web Application Client (Authorization Code Flow)
         *
         * Grant Type: AUTHORIZATION_CODE + REFRESH_TOKEN
         * Use Case: Web applications with backend (most secure for user authentication)
         * Examples: React + Spring Boot, Angular + Java backend
         *
         * Characteristics:
         * - User authenticates via browser redirect
         * - Most secure flow (client never sees password)
         * - Supports refresh tokens
         * - Requires consent screen
         *
         * Redirect URIs: Where to send authorization code after user login
         */
        RegisteredClient webAppClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("web-app-client")
                .clientSecret(passwordEncoder.encode("web-app-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/web-app-client")
                .redirectUri("http://127.0.0.1:8080/authorized")

                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")

                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())

                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)  // Show consent screen
                        .build())
                .build();

        /**
         * Client 4: Public Client (Flexible)
         *
         * Grant Types: AUTHORIZATION_CODE + CLIENT_CREDENTIALS + REFRESH_TOKEN
         * Use Case: Testing and backward compatibility
         *
         * Supports multiple grant types for flexibility.
         */
        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/public-client")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        // Register ALL clients
        return new InMemoryRegisteredClientRepository(
                userClient,
                appClient,
                webAppClient,
                publicClient
        );
    }


}
