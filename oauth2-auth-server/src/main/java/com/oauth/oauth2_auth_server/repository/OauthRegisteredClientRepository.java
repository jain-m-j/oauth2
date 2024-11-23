package com.oauth.oauth2_auth_server.repository;

import com.oauth.oauth2_auth_server.entity.OauthRegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OauthRegisteredClientRepository extends JpaRepository<OauthRegisteredClientEntity, String> {

    Optional<OauthRegisteredClientEntity> findByClientId(String clientId);

}

