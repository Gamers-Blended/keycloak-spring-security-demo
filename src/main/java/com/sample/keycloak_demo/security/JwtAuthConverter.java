package com.sample.keycloak_demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Value("${jwt.auth.converter.principal-attribute}")
    private String principalAttribute;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceID;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                // concatenate both streams
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()
        ).collect(Collectors.toSet());
        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipalClaimName(jwt)
        );
    }

    private String getPrincipalClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB; // default subject
        // case for different attribute name
        // Keycloak generated jwt SUB is a generated internal ID, cannot use
        if (null != principalAttribute) {
            claimName = principalAttribute;
        }
        return jwt.getClaim(claimName);
    }

    // collection input = anything that extends GrantedAuthority
    // returns a collection of roles extracted from jwt with "ROLE_" prefix appended
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource; // client-id
        Collection<String> resourceRoles; // stores roles extracted from jwt
        // inspect jwt in jwt.io
        if (null == jwt.getClaim("resource_access")) {
            return Set.of();
        }
        resourceAccess = jwt.getClaim("resource_access");

        // resource ID
        if (null == resourceAccess.get(resourceID)) {
            return Set.of();
        }
        resource = (Map<String, Object>) resourceAccess.get(resourceID);

        resourceRoles = (Collection<String>) resource.get("roles");
        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role)) // add ROLE_ prefix
                .collect(Collectors.toSet());
    }
}
