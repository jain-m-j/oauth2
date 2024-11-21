package com.oauth.oauth2_resource_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/products/**").authenticated() // Access control based on
                        // scope
                        .anyRequest().authenticated() // All other requests require authentication
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt()) // Enable OAuth2 resource server with JWT decoding
                .build();
    }
}