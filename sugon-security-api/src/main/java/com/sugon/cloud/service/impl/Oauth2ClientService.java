package com.sugon.cloud.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.sugon.cloud.entity.Oauth2ClientEntity;
import com.sugon.cloud.enums.AuthorizationGrantTypeEnum;
import com.sugon.cloud.enums.ClientAuthenticationMethodEnum;
import com.sugon.cloud.mapper.Oauth2ClientMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.util.*;
import java.util.function.Consumer;

@Service
@Slf4j
public class Oauth2ClientService  implements RegisteredClientRepository{

    @Autowired
    private  Oauth2ClientMapper oauth2ClientMapper;
    @Autowired
    private  PasswordEncoder passwordEncoder;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private  RedisTemplate redisTemplate;

    public static final String CLIENT_PREFIX = "client_id:";

    @PostConstruct
    public void init() {
        List<Oauth2ClientEntity> list = oauth2ClientMapper.selectAll();
        //delete old redis
        Set<String> keys = redisTemplate.keys(CLIENT_PREFIX + "*");
        if (!CollectionUtils.isEmpty(keys)) {
            redisTemplate.delete(keys);
        }
        if (!CollectionUtils.isEmpty(list)) {
            list.forEach(oauth2ClientEntity -> {
                redisTemplate.opsForValue().set(CLIENT_PREFIX + oauth2ClientEntity.getClientId(), oauth2ClientEntity);
            });
        }
    }


    @Transactional
    public Oauth2ClientEntity create(Oauth2ClientEntity oauth2ClientEntity) throws Exception {

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
        String id = UUID.randomUUID().toString();
        RegisteredClient loginClient = RegisteredClient.withId(id)
                .clientId(oauth2ClientEntity.getClientId())
                .clientSecret(passwordEncoder.encode(oauth2ClientEntity.getClientSecret()))
                .clientAuthenticationMethods(getClientAuthenticationMethod(oauth2ClientEntity))
                .authorizationGrantTypes(getAuthorizationGrantType(oauth2ClientEntity))
                .redirectUris(strings -> strings.addAll(oauth2ClientEntity.getRedirectUri()))
                .scopes(strings -> strings.addAll(oauth2ClientEntity.getScope()))
                .clientSecretExpiresAt(Objects.isNull(oauth2ClientEntity.getClientSecretExpiresAt())? null: oauth2ClientEntity.getClientSecretExpiresAt())
                .tokenSettings(TokenSettings.builder().build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        registeredClientRepository.save(loginClient);
        UpdateWrapper<Oauth2ClientEntity> updateWrapper = new UpdateWrapper<Oauth2ClientEntity>().set("type", oauth2ClientEntity.getType())
                .eq("id", id);
        oauth2ClientEntity.setId(id);
        oauth2ClientMapper.update(oauth2ClientEntity, updateWrapper);
        redisTemplate.opsForValue().set(CLIENT_PREFIX + oauth2ClientEntity.getClientId(), oauth2ClientEntity);
        return oauth2ClientEntity;
    }


    private Consumer<Set<ClientAuthenticationMethod>> getClientAuthenticationMethod(Oauth2ClientEntity oauth2ClientEntity) throws Exception {
        Set<ClientAuthenticationMethod> result = new HashSet<>();
        if (!StringUtils.isEmpty(oauth2ClientEntity.getClientAuthenticationMethods())) {
            for (String clientAuthenticationMethodEnum : oauth2ClientEntity.getClientAuthenticationMethods().split(",")) {
                switch (ClientAuthenticationMethodEnum.getByValue(clientAuthenticationMethodEnum)) {
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
                    default:
                        throw new Exception("没有这种客户端授权方式");
                }
            }

        }

        Consumer<Set<ClientAuthenticationMethod>> setConsumer = clientAuthenticationMethods -> {
            clientAuthenticationMethods.addAll(result);
        };


        return setConsumer;
    }
    
  

    private Consumer<Set<String>> getSeperates(String urls) {
        if (StringUtils.isEmpty(urls)) {
            return  clientAuthenticationMethods -> {};
        }
        String [] url  =  urls.split(",");
        Set<String> urlSet = new HashSet<>();
        for (String s : url) {
            urlSet.add(s);
        }
        Consumer<Set<String>> setConsumer = clientAuthenticationMethods -> {
            clientAuthenticationMethods.addAll(urlSet);
        };
        return setConsumer;
    }

    public RegisteredClient getByClientEntity(Oauth2ClientEntity oauth2ClientEntity) throws Exception {

        if (Objects.isNull(oauth2ClientEntity)) {
            return null;
        }
        RegisteredClient loginClient = RegisteredClient.withId(oauth2ClientEntity.getId())
                .clientId(oauth2ClientEntity.getClientId())
                .clientSecret(oauth2ClientEntity.getClientSecret())
                .clientAuthenticationMethods(getClientAuthenticationMethod(oauth2ClientEntity))
                .authorizationGrantTypes(getAuthorizationGrantType(oauth2ClientEntity))
                .redirectUris(getSeperates(oauth2ClientEntity.getRedirectUris()))
                .scopes(getSeperates(oauth2ClientEntity.getScopes()))
                .clientSecretExpiresAt(Objects.isNull(oauth2ClientEntity.getClientSecretExpiresAt())? null: oauth2ClientEntity.getClientSecretExpiresAt())
                .tokenSettings(TokenSettings.builder().build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return loginClient;
    }

    private Consumer<Set<AuthorizationGrantType>> getAuthorizationGrantType(Oauth2ClientEntity oauth2ClientEntity) throws Exception {
        Set<AuthorizationGrantType> result = new HashSet<>();
        if (!StringUtils.isEmpty(oauth2ClientEntity.getAuthorizationGrantTypes())) {
            for (String authorizationGrantTypeEnum : oauth2ClientEntity.getAuthorizationGrantTypes().split(",")) {
                switch (AuthorizationGrantTypeEnum.getByValue(authorizationGrantTypeEnum)) {
                    case IMPLICIT:
                        result.add(AuthorizationGrantType.IMPLICIT);
                        break;
                    case PASSWORD:
                        result.add(AuthorizationGrantType.PASSWORD);
                        break;
                    case REFRESH_TOKEN:
                        result.add(AuthorizationGrantType.REFRESH_TOKEN);
                        break;
                    case JWT_BEARER:
                        result.add(AuthorizationGrantType.JWT_BEARER);
                    case CLIENT_CREDENTIALS:
                        result.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    default:
                        throw new Exception("没有这种授权类型");
                }
            }
        }
        result.add(AuthorizationGrantType.AUTHORIZATION_CODE);
        Consumer<Set<AuthorizationGrantType>> consumer = authorizationGrantTypes -> {
            authorizationGrantTypes.addAll(result);
        };
        return consumer;
    }


   


    @Override
    public void save(RegisteredClient registeredClient) {
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource));
        registeredClientRepository.save(registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        log.warn("find client by id method is not completed");
        return null;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Oauth2ClientEntity oauth2ClientEntity = (Oauth2ClientEntity) redisTemplate.opsForValue().get(CLIENT_PREFIX + clientId);
        if (Objects.isNull(oauth2ClientEntity)) {
            LambdaQueryWrapper queryWrapper = new LambdaQueryWrapper<Oauth2ClientEntity>().eq(Oauth2ClientEntity::getClientId, clientId);
            oauth2ClientEntity = oauth2ClientMapper.selectOne(queryWrapper);
        }
        try {
            RegisteredClient registeredClient = getByClientEntity(oauth2ClientEntity);
            return registeredClient;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
}
