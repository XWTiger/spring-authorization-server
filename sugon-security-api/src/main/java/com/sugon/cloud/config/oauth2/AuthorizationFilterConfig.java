package com.sugon.cloud.config.oauth2;

import com.sugon.cloud.filter.PasswordGrantFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;

/**
 * @author ti'ge'r
 * 添加 password 类型的 token 认证，结合gateway，redis 实现高性能版本
 */
@Configuration
public class AuthorizationFilterConfig {

    private final PasswordGrantFilter passwordGrantFilter;
    @Autowired
    @SuppressWarnings("unused")
    public AuthorizationFilterConfig(PasswordGrantFilter passwordGrantFilter) {
        this.passwordGrantFilter = passwordGrantFilter;
    }

    @Bean
    @Order(4)
    @SuppressWarnings("unused")
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        RequestMatcher passwordGrantEndPointMatcher = new AntPathRequestMatcher("/oauth/token");

        // Custom User Info Mapper that retrieves claims from a signed JWT
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
            return new OidcUserInfo(principal.getToken().getClaims());
        };

        http
                .requestMatchers()
                .requestMatchers(endpointsMatcher, passwordGrantEndPointMatcher)
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/token").permitAll()
                .antMatchers("/api/salt").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
                .apply(authorizationServerConfigurer)
                .oidc(oidc -> oidc
                        .clientRegistrationEndpoint(Customizer.withDefaults())
                        .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper))
                )
                .and()
                .addFilterBefore(passwordGrantFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .formLogin()
                .loginPage("/login")
                .and()
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

   /*@Bean
    @Order(3)
    public void whiteList(HttpSecurity http) throws Exception {

         http
                .authorizeRequests()
                .antMatchers("/api/salt").permitAll()
                .and()

                //.antMatchers("/api/oauth2/client").permitAll()

//                .and()
//                .csrf()
//                .disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .invalidSessionUrl("/api/salt")
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .successForwardUrl("/doc.html")
//                .and()
//                .exceptionHandling(exceptions ->
//                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//                )
               // .build()

         ;

    }*/
}
