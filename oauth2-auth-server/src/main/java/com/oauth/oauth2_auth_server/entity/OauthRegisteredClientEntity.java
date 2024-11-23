package com.oauth.oauth2_auth_server.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "oauth2_registered_client")
public class OauthRegisteredClientEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String clientId;
    private String clientSecret;
    private String authorizationGrantType;
    private String scopes;
    private long tokenSettings;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    public void setAuthorizationGrantType(String authorizationGrantType) {
        this.authorizationGrantType = authorizationGrantType;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public long getTokenSettings() {
        return tokenSettings;
    }

    public void setTokenSettings(long tokenSettings) {
        this.tokenSettings = tokenSettings;
    }
}
