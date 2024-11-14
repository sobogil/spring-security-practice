package com.example.springsecurity.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthSecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl) requests.anyRequest()).authenticated();
        });
        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        //http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.csrf().disable();
        return (SecurityFilterChain) http.build();
    }
}
