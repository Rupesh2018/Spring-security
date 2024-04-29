package com.dncoyote.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.dncoyote.springsecurity.entity.Role;
import com.dncoyote.springsecurity.service.UserService;

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
                        .requestMatchers("/api/v1/admin/**").hasAnyAuthority(Role.ADMIN.name())
                        .requestMatchers("/api/v1/user/**").hasAnyAuthority(Role.USER.name())
                        .anyRequest().authenticated())

                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        // .logout()
        // .logoutUrl("/api/v1/auth/logout")
        // .addLogoutHandler(logoutHandler)
        // .logoutSuccessHandler((request, response, authentication) ->
        // SecurityContextHolder.clearContext());
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

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userService.userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
