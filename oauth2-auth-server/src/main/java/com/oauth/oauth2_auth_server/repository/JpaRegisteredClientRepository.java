package com.oauth.oauth2_auth_server.repository;

import com.oauth.oauth2_auth_server.entity.OauthRegisteredClientEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OauthRegisteredClientRepository oauthRegisteredClientRepository;
    private final PasswordEncoder passwordEncoder;

    public JpaRegisteredClientRepository(OauthRegisteredClientRepository oauthRegisteredClientRepository, PasswordEncoder passwordEncoder) {
        this.oauthRegisteredClientRepository = oauthRegisteredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        return null;
    }

    public RegisteredClient findByClientId(String clientId) {
        Optional<OauthRegisteredClientEntity> oauthRegisteredClientEntity = oauthRegisteredClientRepository.findByClientId(clientId);
        return oauthRegisteredClientEntity.map(oauthRegisteredClient -> RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(oauthRegisteredClient.getClientId())
                .clientSecret(passwordEncoder.encode(oauthRegisteredClient.getClientSecret()))
                .authorizationGrantType(new AuthorizationGrantType(oauthRegisteredClient.getAuthorizationGrantType()))
                .scope(oauthRegisteredClient.getScopes())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(oauthRegisteredClient.getTokenSettings()))
                        .build())
                .build()).orElse(null);
    }

}
