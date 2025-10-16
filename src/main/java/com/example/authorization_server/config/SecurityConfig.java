package com.example.authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;


@Configuration
public class SecurityConfig {


    /**
     * OAuth2 Authorization Server Security Filter Chain
     * Handles all OAuth2 and OIDC endpoints:
     * - /oauth2/authorize
     * - /oauth2/token
     * - /oauth2/jwks
     * - /oauth2/introspect
     * - /oauth2/revoke
     * - /userinfo
     * - /.well-known/openid-configuration
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Step 1: Apply OAuth 2.0 security for specific endpoints
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Step 2: Enable OpenID connect
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // Step 3: Redirect unauthenticated users to login
        http.exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                ));

        // Step 4: Validate JWT tokens for protected endpoints
        http.oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults())
        );

        return http.build();
    }

    /**
     * Default Security Filter Chain

     * Handles everything NOT handled by the OAuth2 filter chain:
     * - /login (form login)
     * - /logout
     * - Any custom endpoints
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers("/api/auth/**").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }




    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


}
