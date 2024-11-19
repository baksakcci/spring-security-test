package sangcci.springsecuritytest.common.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import sangcci.springsecuritytest.auth.util.JwtProvider;
import sangcci.springsecuritytest.auth.filter.JwtAuthenticationFilter;
import sangcci.springsecuritytest.auth.filter.JwtAuthorizationFilter;
import sangcci.springsecuritytest.auth.oauth2.application.CustomOAuth2UserService;
import sangcci.springsecuritytest.auth.oauth2.handler.OAuth2LoginFailureHandler;
import sangcci.springsecuritytest.auth.oauth2.handler.OAuth2LoginSuccessHandler;
import sangcci.springsecuritytest.auth.handler.CustomAccessDeniedHandler;
import sangcci.springsecuritytest.auth.handler.CustomAuthenticationEntryPoint;
import sangcci.springsecuritytest.auth.handler.LoginFailureHandler;
import sangcci.springsecuritytest.auth.handler.LoginSuccessHandler;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] ALLOW_URLS = {"/h2-console/**"};
    private static final String[] AUTH_URLS = {"/api/auth/**"};

    // JWT
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final JwtAuthorizationFilter jwtAuthorizationFilter;
    // OAuth2
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;

    /**
     * 이 메서드는 정적 자원에 대해 보안을 적용하지 않도록 설정한다. 정적 자원은 보통 HTML, CSS, JavaScript, 이미지 파일 등을 의미하며, 이들에 대해 보안을 적용하지 않음으로써 성능을
     * 향상시킬 수 있다.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                .csrf(CsrfConfigurer<HttpSecurity>::disable)
                .formLogin(FormLoginConfigurer<HttpSecurity>::disable)
                .httpBasic(HttpBasicConfigurer<HttpSecurity>::disable)
                .headers(it -> it.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .sessionManagement(it ->
                        it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(AUTH_URLS).permitAll()
                        .requestMatchers(ALLOW_URLS).permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/manager/**").hasRole("MANAGER")
                        .anyRequest().authenticated()
                )
                .httpBasic(AbstractHttpConfigurer::disable);

        http
                .exceptionHandling(exception -> exception.authenticationEntryPoint(customAuthenticationEntryPoint))
                .exceptionHandling(exception -> exception.accessDeniedHandler(customAccessDeniedHandler));

        http
                .addFilterAfter(jwtAuthenticationFilter, LogoutFilter.class)
                .addFilterBefore(jwtAuthorizationFilter, JwtAuthenticationFilter.class);

        http
                .oauth2Login(customConfigurer -> customConfigurer
                        .authorizationEndpoint(end -> end.baseUri("/api/v1/oauth2/login"))
                        .userInfoEndpoint(endPointConfig -> endPointConfig.userService(customOAuth2UserService))
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler(oAuth2LoginFailureHandler));

        return http.build();
    }

    /*@Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("""
                ROLE_ADMIN > ROLE_MANAGER
                ROLE_MANAGER > ROLE_TEAM
                """);
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            AuthenticationManager authenticationManager,
            JwtProvider jwtProvider
    ) {
        JwtAuthenticationFilter authenticationFilter = new JwtAuthenticationFilter();
        authenticationFilter.setAuthenticationManager(authenticationManager);
        authenticationFilter.setAuthenticationSuccessHandler(new LoginSuccessHandler(jwtProvider));
        authenticationFilter.setAuthenticationFailureHandler(new LoginFailureHandler());
        return authenticationFilter;
    }
}
