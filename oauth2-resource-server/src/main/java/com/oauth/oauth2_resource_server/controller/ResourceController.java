package com.oauth.oauth2_resource_server.controller;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/protected")
    public String protectedResource(Authentication authentication) {
        // Extract authorities from the Authentication object
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // Print authorities
        authorities.forEach(authority -> System.out.println("Authority: " + authority.getAuthority()));

        return "This is a protected resource!";
    }

    @GetMapping("/public")
    public String publicResource() {
        return "This is a public resource!";
    }
}
