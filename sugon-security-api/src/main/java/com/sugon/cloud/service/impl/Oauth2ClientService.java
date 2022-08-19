package com.sugon.cloud.service.impl;

import com.sugon.cloud.entity.Oauth2ClientEntity;
import com.sugon.cloud.enums.ClientAuthenticationMethodEnum;
import com.sugon.cloud.mapper.Oauth2ClientMapper;
import jdk.internal.dynalink.support.NameCodec;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class Oauth2ClientService {

    private final Oauth2ClientMapper oauth2ClientMapper;
    private final PasswordEncoder passwordEncoder;

    public Oauth2ClientEntity create(Oauth2ClientEntity oauth2ClientEntity) {
        RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(oauth2ClientEntity.getClientId())
                .clientSecret(passwordEncoder.encode(oauth2ClientEntity.getClientSecret()))
                .clientAuthenticationMethods(getClientAuthenticationMethod(oauth2ClientEntity))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/login-client")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(TokenSettings.builder().build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return null;
    }

    private Consumer<Set<ClientAuthenticationMethod>> getClientAuthenticationMethod(Oauth2ClientEntity oauth2ClientEntity) {
        Set<ClientAuthenticationMethod> result = new HashSet<>();
        if (!CollectionUtils.isEmpty(oauth2ClientEntity.getClientAuthenticationMethods())) {
            oauth2ClientEntity.getClientAuthenticationMethods().forEach(clientAuthenticationMethodEnum -> {
                switch (clientAuthenticationMethodEnum){
                    case CLIENT_SECRET_BASIC:
                        result.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                        break;
                    case CLIENT_SECRET_POST:
                        result.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                        break;
                    case CLIENT_SECRET_JWT:
                        result.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
                        break;
                    case PRIVATE_KEY_JWT:
                        result.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
                        break;
                    case NONE:
                        result.add(ClientAuthenticationMethod.NONE);
                        break;
                }
            });

        }

        Consumer<Set<ClientAuthenticationMethod>> setConsumer = clientAuthenticationMethods -> {

        };

        return setConsumer;
    }


}
