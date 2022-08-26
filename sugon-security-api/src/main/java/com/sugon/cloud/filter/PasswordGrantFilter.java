package com.sugon.cloud.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sugon.cloud.common.ResultModel;
import com.sugon.cloud.service.impl.AuthService;
import com.sugon.cloud.utils.CommonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
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

   @Autowired
   public PasswordGrantFilter(AuthService authService) {
      this.authService = authService;
      this.authEndpointMatcher = createDefaultRequestMatcher();
   }

   @SuppressWarnings("NullableProblems")
   @Override
   protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
      if (!this.authEndpointMatcher.matches(request)) {
         filterChain.doFilter(request, response);
         return;
      }

      byte[] entity = new byte[0];
      try {
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
}
