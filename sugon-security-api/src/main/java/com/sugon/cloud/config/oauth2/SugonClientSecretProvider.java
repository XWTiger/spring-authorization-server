package com.sugon.cloud.config.oauth2;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@AllArgsConstructor
public class SugonClientSecretProvider implements AuthenticationProvider {
    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken auth = (OAuth2ClientAuthenticationToken) authentication;
        RegisteredClient registeredClient = registeredClientRepository.findByClientId((String) auth.getPrincipal());
        String cred = (String) authentication.getCredentials();
        if (passwordEncoder.matches(cred, registeredClient.getClientSecret())) {
            return authentication;
        } else throw new AuthenticationException("客户端令牌错误"){
            @Override
            public String getMessage() {
                super.getMessage();
                return "客户端令牌错误";
            }
        };
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
