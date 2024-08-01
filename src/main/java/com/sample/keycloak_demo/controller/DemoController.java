package com.sample.keycloak_demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/keycloak")
public class DemoController {

    @GetMapping
    @PreAuthorize("hasRole('client_user')")
    public String helloForUser() {
        return "Hello from Spring Boot & Keycloak - USER";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('client_admin')")
    public String helloForAdmin() {
        return "Hello from Spring Boot & Keycloak - ADMIN";
    }
}
