package com.dncoyote.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JWTAuthenticationFilter jwtAuthenticationFilter;

    private final UserService userService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer.disable)
                .authorizeHttpRequests(request -> request.requestMatchers("/api/v1/auth/**")
                    .permitAll()
                    .requestMatchers())
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());
        // .logout(logout -> logout.logoutUrl("/api/v1/auth/logout")
        // .addLogoutHandler(logoutHandler)
        // .logoutSuccessHandler(
        // (request, response, authentication) ->
        // SecurityContextHolder.clearContext()));

        // http
        // .csrf(AbstractHttpConfigurer::disable)
        // .authorizeHttpRequests(req -> req.requestMatchers(WHITE_LIST_URL)
        // .permitAll()
        // .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(),
        // MANAGER.name())
        // .requestMatchers(GET, "/api/v1/management/**")
        // .hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
        // .requestMatchers(POST, "/api/v1/management/**")
        // .hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
        // .requestMatchers(PUT, "/api/v1/management/**")
        // .hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
        // .requestMatchers(DELETE, "/api/v1/management/**")
        // .hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
        // .anyRequest()
        // .authenticated())
        // .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
        // .authenticationProvider(authenticationProvider)
        // .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        // .logout(logout -> logout.logoutUrl("/api/v1/auth/logout")
        // .addLogoutHandler(logoutHandler)
        // .logoutSuccessHandler(
        // (request, response, authentication) ->
        // SecurityContextHolder.clearContext()));

        return http.build();
    }

}
