package com.sugon.cloud.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sugon.cloud.config.oauth2.SugonClientSecretProvider;
import com.sugon.cloud.entity.AuthResult;
import com.sugon.cloud.entity.Oauth2ClientEntity;
import com.sugon.cloud.entity.RamUserEntity;
import com.sugon.cloud.service.PhoneCodeService;
import com.sugon.cloud.utils.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class AuthService {
   private final AuthenticationManager authenticationManager;
   private final OAuth2AuthorizationCodeRequestAuthenticationProvider oAuth2AuthorizationCodeRequestAuthenticationProvider;
   private final OAuth2AuthorizationCodeAuthenticationProvider oAuth2AuthorizationCodeAuthenticationProvider;
   /* private final ClientSecretAuthenticationProvider clientSecretAuthenticationProvider;*/
   private final SugonClientSecretProvider sugonClientSecretProvider;
   private final ObjectMapper objectMapper;
   private final RedisTemplate redisTemplate;
   private final UserDetailsServiceImpl userDetailsService;

   private final PhoneCodeService phoneCodeService;

   private final int FAILED_TIMES = 10;
   private final static String USER_NAME = "comments";
   private final static String NICK_NAME = "lastName";
   public final static String TOKEN_HEADER = "auth:";
   private static final String LOCAL_AUTHORIZATION_URI = "http://localhost:8090/oauth2/authorize";

   @Value("${authorization.token-expire:1800}")
   private Long expire;

   @Value("${authorization.user-lock-time:600}")
   private Long lockTime;

   @Autowired
   public AuthService(
         @Lazy AuthenticationManager authenticationManager,
         RegisteredClientRepository registeredClientRepository,
         @Lazy OAuth2AuthorizationService authorizationService,
         @Lazy OAuth2AuthorizationConsentService authorizationConsentService,
        /* ClientSecretAuthenticationProvider clientSecretAuthenticationProvider,*/
         SugonClientSecretProvider sugonClientSecretProvider,
         OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
          RedisTemplate redisTemplate,UserDetailsServiceImpl userDetailsService,
         @Nullable  PhoneCodeService phoneCodeService
         ) {

      this.authenticationManager = authenticationManager;
      this.oAuth2AuthorizationCodeRequestAuthenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService);
      this.sugonClientSecretProvider = sugonClientSecretProvider;
     /* this.clientSecretAuthenticationProvider = clientSecretAuthenticationProvider;*/
      this.oAuth2AuthorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService, tokenGenerator
      );

      this.objectMapper = new ObjectMapper();
      this.redisTemplate = redisTemplate;
      this.userDetailsService = userDetailsService;
      this.phoneCodeService = phoneCodeService;
   }

   public String getAccessTokenForRequest(HttpServletRequest request) throws Exception {
      RamUserEntity userEntity = null;
      Authentication principal = null;

      //添加手机校验码逻辑
      if (!Objects.isNull(phoneCodeService)) {
         if (!phoneCodeService.checkPhoneCode(request)) {
            throw  new Exception("手机验证码错误");
         }
      } else {
         // 密码验证
         String userName = request.getParameter("username");
         Assert.notNull(userName, "账号不能为空");

         //判断是否被锁定
         String lockedUser = UserDetailsServiceImpl.LOCKED_HEADER + userName;
         if (redisTemplate.hasKey(lockedUser)) {
            Integer locked = (Integer) redisTemplate.opsForValue().get(lockedUser);
            if (locked >= FAILED_TIMES) {
               throw new Exception("用户名或者密码错误过多，" + expire / 60 + "分钟后再试");
            }
         }
         String passwordInBase64 = request.getParameter("password");
         Assert.hasText(passwordInBase64, "密码不能为空");

         //秘钥解密
         String publicKey = request.getParameter("publicKey");
         if (org.apache.commons.lang3.StringUtils.isEmpty(publicKey)) {
            throw new Exception("缺少公钥");
         }
         String specialKey = userName;


         try {
            userEntity = userDetailsService.loadUserByUserName(userName);
            String specialValue = decrypt(publicKey, passwordInBase64);
            if (Objects.isNull(userEntity)) {
               throw new Exception("用户已经不存在");
            }


            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(specialKey, specialValue);
            principal = authenticationManager.authenticate(authRequest);


         } catch (Exception e) {
            e.printStackTrace();
            // 如果验证失败10次 锁 10分钟
            if (StringUtils.hasLength(userName)) {
               if (redisTemplate.hasKey(lockedUser)) {
                  redisTemplate.opsForValue().increment(lockedUser);
               } else {
                  redisTemplate.opsForValue().set(lockedUser, 1, lockTime, TimeUnit.SECONDS);
               }
            }
            throw e;
         }
      }

      try {
         // from org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.doFilterInternal
         // from org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter.convert
         // client 获取
         String authBasic = request.getHeader("Authorization");
         if (org.apache.commons.lang3.StringUtils.isEmpty(authBasic)) {
            throw new Exception("缺少client Authorization认证");
         }
         String decodeAuthBasic = new String(Base64.getDecoder().decode(authBasic));
         String[] sperator = decodeAuthBasic.split(":");
         if (org.apache.commons.lang3.StringUtils.isEmpty(sperator[0]) || org.apache.commons.lang3.StringUtils.isEmpty(sperator[1])) {
            throw new Exception("client Authorization 格式不正确");
         }
         Oauth2ClientEntity oauth2ClientEntity = (Oauth2ClientEntity) redisTemplate.opsForValue().get(Oauth2ClientService.CLIENT_PREFIX + sperator[0]);
         if (Objects.isNull(oauth2ClientEntity)) {
            throw new Exception("令牌不正确");
         }
         OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = new OAuth2ClientAuthenticationToken(sperator[0], ClientAuthenticationMethod.CLIENT_SECRET_BASIC, sperator[1], null);
         // 验证令牌
         sugonClientSecretProvider.authenticate(oAuth2ClientAuthenticationToken);



     /*    OAuth2AuthorizationCodeRequestAuthenticationToken requestAuthenticationToken =
               OAuth2AuthorizationCodeRequestAuthenticationToken.with(oauth2ClientEntity.getClientId(), principal)
                     .authorizationUri(LOCAL_AUTHORIZATION_URI)
                     .consentRequired(false)
                     .scopes(oauth2ClientEntity.getScopes())
                     .redirectUri(oauth2ClientEntity.getRedirectUris())
                     .state("STATE").build();

         OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
               (OAuth2AuthorizationCodeRequestAuthenticationToken) oAuth2AuthorizationCodeRequestAuthenticationProvider.authenticate(requestAuthenticationToken);

         // from org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter.doFilterInternal
         // from org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter.convert
         Map<String, Object> params = new HashMap<>();
         OAuth2AuthorizationCode authorizationCode = authorizationCodeRequestAuthenticationResult.getAuthorizationCode();
         params.put("code", authorizationCode == null ? "EMPTY" : authorizationCodeRequestAuthenticationResult.getAuthorizationCode().getTokenValue());
         params.put("redirect_uri", oauth2ClientEntity.getRedirectUris());
         params.put("grant_type", "authorization_code");
         params.put("client_id", oauth2ClientEntity.getClientId());
         OAuth2ClientAuthenticationToken clientAuthenticationToken = new OAuth2ClientAuthenticationToken(oauth2ClientEntity.getClientId(),
               ClientAuthenticationMethod.CLIENT_SECRET_BASIC, oauth2ClientEntity.getClientSecret(), params);

         Authentication clientAuthenticationResult = clientSecretAuthenticationProvider.authenticate(clientAuthenticationToken);

         OAuth2AuthorizationCodeAuthenticationToken codeToken = new OAuth2AuthorizationCodeAuthenticationToken(
               authorizationCodeRequestAuthenticationResult.getAuthorizationCode().getTokenValue(), clientAuthenticationResult,
               authProperties.getRedirectUri(), new LinkedHashMap<>());

         ProviderSettings providerSettings = ProviderSettings.builder().issuer(oauth2ClientEntity.getIssuerUri()).build();
         ProviderContextHolder.setProviderContext(new ProviderContext(providerSettings, null));

        /OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
               (OAuth2AccessTokenAuthenticationToken) oAuth2AuthorizationCodeAuthenticationProvider.authenticate(codeToken);*/

         // from org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter.sendAccessTokenResponse
         String accessUUIDToken = UUID.randomUUID().toString();
         redisTemplate.opsForValue().set(TOKEN_HEADER + accessUUIDToken, userEntity, expire, TimeUnit.SECONDS);

         AuthResult result = AuthResult.builder()
                 .accessToken(accessUUIDToken)
                 .comments(StringUtils.isEmpty(userEntity.getComments()) ? userEntity.getDisplayName() : userEntity.getComments())
                 .expiresIn(redisTemplate.opsForValue().getOperations().getExpire(TOKEN_HEADER + accessUUIDToken))
                 .lastLogin(userEntity.getLastLogin())
                 .roleType(Arrays.asList(userEntity.getType().split(",")))
                 .scope(oauth2ClientEntity.getScopes())
                 .tokenType("bearer")
                 .username(userEntity.getUserName())
                 .userId(userEntity.getId())
                 .lastPasswordTime(userEntity.getLastPasswordTime())
                 .build();

         return objectMapper.writeValueAsString(result);
      } catch (Exception ex) {
         log.error("error in get token >>>", ex);
         throw new RuntimeException(ex); // TODO security
      }
   }
   private String decrypt (String publicKey, String password) throws Exception {
      String privateKey = (String) redisTemplate.opsForValue().get(publicKey);
      //redisTemplate.delete(publicKey);
      String decryptPassword = null;
      if (!StringUtils.hasLength(privateKey)) {
         throw new Exception("解密失败，公钥已经过期");
      }
      try {
         decryptPassword = new String(RSAUtil.decryptByPrivateKey(Base64.getDecoder().decode(password), privateKey));
      } catch (Exception e) {
         e.printStackTrace();
         throw new Exception("解密失败");
      }
      return decryptPassword;
   }

   public Map<String, Object> convert(OAuth2AccessTokenResponse tokenResponse) {
      Map<String, Object> parameters = new HashMap<>();
      parameters.put(OAuth2ParameterNames.ACCESS_TOKEN, tokenResponse.getAccessToken().getTokenValue());
      parameters.put(OAuth2ParameterNames.TOKEN_TYPE, tokenResponse.getAccessToken().getTokenType().getValue());
      parameters.put(OAuth2ParameterNames.EXPIRES_IN, getExpiresIn(tokenResponse));
      if (!CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
         parameters.put(OAuth2ParameterNames.SCOPE,
               StringUtils.collectionToDelimitedString(tokenResponse.getAccessToken().getScopes(), " "));
      }
      if (tokenResponse.getRefreshToken() != null) {
         parameters.put(OAuth2ParameterNames.REFRESH_TOKEN, tokenResponse.getRefreshToken().getTokenValue());
      }
      if (!CollectionUtils.isEmpty(tokenResponse.getAdditionalParameters())) {
         parameters.putAll(tokenResponse.getAdditionalParameters());
      }
      return parameters;
   }

   private long getExpiresIn(OAuth2AccessTokenResponse tokenResponse) {
      if (tokenResponse.getAccessToken().getExpiresAt() != null) {
         return ChronoUnit.SECONDS.between(Instant.now(), tokenResponse.getAccessToken().getExpiresAt());
      }
      return -1;
   }


}

