package com.sugon.cloud.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sugon.cloud.common.ResultModel;
import com.sugon.cloud.entity.RamUserEntity;
import com.sugon.cloud.service.impl.AuthService;
import com.sugon.cloud.utils.CommonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.util.matcher.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

/**
 * @author ti'ge'r
 * 自定义 password filter
 */
@Component
public class PasswordGrantFilter extends OncePerRequestFilter {
   private static final String DEFAULT_AUTH_ENDPOINT_URI = "/oauth/token";

   private final RequestMatcher authEndpointMatcher;
   private final AuthService authService;
   private final RedisTemplate redisTemplate;
   private final RequestMatcher whiteEndPointMatcher;

   @Autowired
   public PasswordGrantFilter(AuthService authService, RedisTemplate redisTemplate) {
      this.authService = authService;
      this.authEndpointMatcher = createDefaultRequestMatcher();
      this.redisTemplate = redisTemplate;
      this.whiteEndPointMatcher = createWhiteRequestMatcher();
   }

   @SuppressWarnings("NullableProblems")
   @Override
   protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
      byte[] entity = new byte[0];
      try {
         if (!this.authEndpointMatcher.matches(request)) {
            //如果不是验证就校验token
            checkToken(request);
            filterChain.doFilter(request, response);
            return;
         }



            entity = authService.getAccessTokenForRequest(request).getBytes(StandardCharsets.UTF_8);
      } catch (Exception e) {
         e.printStackTrace();
         response.setStatus(SC_UNAUTHORIZED);
         response.setContentType("application/json");
         ResultModel result;

         if (CommonUtils.isContainChinese(e.getMessage())) {
            result = ResultModel.error(e.getMessage());
         } else {
            result = ResultModel.error("认证失败, 请联系管理员!");
         }
         response.getOutputStream().write(new ObjectMapper().writer().writeValueAsBytes(result));
      }
      response.getOutputStream().write(entity);
      response.setContentType("application/json");
   }

   private static RequestMatcher createDefaultRequestMatcher() {
      RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
            DEFAULT_AUTH_ENDPOINT_URI, HttpMethod.GET.name());
      RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
            DEFAULT_AUTH_ENDPOINT_URI, HttpMethod.POST.name());
      RequestMatcher openidScopeMatcher = request -> {
         String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
         return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
      };
      RequestMatcher responseTypeParameterMatcher = request ->
            request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

      RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
            authorizationRequestGetMatcher,
            new AndRequestMatcher(
                  authorizationRequestPostMatcher, responseTypeParameterMatcher, openidScopeMatcher));
      RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
            authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

      return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
   }

   private static RequestMatcher createWhiteRequestMatcher() {
      RequestMatcher whiteRequestGetMatcher = new AntPathRequestMatcher(
              "/api/salt", HttpMethod.GET.name());
      RequestMatcher whiteRequestPostMatcher = new AntPathRequestMatcher(
              "/api/salt", HttpMethod.POST.name());

      RequestMatcher responseTypeParameterMatcher = request ->
              request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

      RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
              whiteRequestGetMatcher,
              new AndRequestMatcher(
                      whiteRequestPostMatcher, responseTypeParameterMatcher));
      RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
              whiteRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

      return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
   }

   private void checkToken(HttpServletRequest request) throws Exception {
      if (this.whiteEndPointMatcher.matches(request)) {
         return;
      }
      String token = request.getHeader("Authorization");
      if (!StringUtils.hasText(token)) {
         token = request.getParameter("token");
      }
      if (!StringUtils.hasText(token)) {
         throw new Exception("Authorization 不能为空");
      }
      String key = AuthService.TOKEN_HEADER + token;
      RamUserEntity ramUserEntity = (RamUserEntity) redisTemplate.opsForValue().get(key);
      if (Objects.isNull(ramUserEntity)) {
         throw new Exception("token 无效");
      }
      Authentication authentication = new Authentication() {
         @Override
         public Collection<? extends GrantedAuthority> getAuthorities() {
            List<GrantedAuthority> list = new ArrayList<>();
            list.add(new SimpleGrantedAuthority("ROLE_" + ramUserEntity.getType()));
            return list;
         }

         @Override
         public Object getCredentials() {
            return null;
         }

         @Override
         public Object getDetails() {
            return ramUserEntity;
         }

         @Override
         public Object getPrincipal() {
            return ramUserEntity.getUserName();
         }

         @Override
         public boolean isAuthenticated() {
            return true;
         }

         @Override
         public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

         }

         @Override
         public String getName() {
            return ramUserEntity.getUserName();
         }
      };
      SecurityContextHolder.getContext().setAuthentication(authentication);

   }
}
