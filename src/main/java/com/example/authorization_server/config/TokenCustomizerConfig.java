package com.example.authorization_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.stream.Collectors;

@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();

            if (principal != null && principal.getAuthorities() != null) {
                // Add authorities
                var authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                context.getClaims().claim("authorities", authorities);

                // Add custom claims
                context.getClaims().claim("username", principal.getName());
                context.getClaims().claim("custom_claim", "custom_value");
                context.getClaims().claim("timestamp", System.currentTimeMillis());
            }
        };
    }
}
