package com.Security.Secureapp.config;

import com.Security.Secureapp.service.UserDetailsServiceImpl; // Import your new service
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider; // Needed for PasswordEncoder
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService; // Keep this import
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // REMOVE THE OLD InMemoryUserDetailsManager BEAN!
    // @Bean
    // public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    //     UserDetails user = User.builder()
    //             .username("user")
    //             .password(passwordEncoder.encode("userpass"))
    //             .roles("USER")
    //             .build();
    //     // ... other in-memory users
    //     return new InMemoryUserDetailsManager(user, admin, viewer);
    // }

    // Instead, rely on your UserDetailsServiceImpl to be picked up as the UserDetailsService
    // Or explicitly define it if you have multiple UserDetailsService implementations
    // For simplicity, if UserDetailsServiceImpl is @Service, Spring will pick it up.

    // OPTIONAL: Configure DaoAuthenticationProvider to explicitly use your UserDetailsService and PasswordEncoder
    // This is often implicitly configured by Spring Boot if there's only one UserDetailsService bean.
    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsServiceImpl userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("--- Custom SecurityFilterChain is being initialized ---");
        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(HttpMethod.GET,
                                "/", "/xss-vulnerable", "/xss-display", "/xss-safe-form", "/xss-display-safe",
                                "/sql-vulnerable", "/sql-search-results", "/sql-safe-jpa", "/sql-safe-hql", "/sql-safe-sp",
                                "/upload-vulnerable", "/upload-status", "/upload-safe", "/download-safe/**", "/uploads-vulnerable/**",
                                "/profile-vulnerable", "/profile",
                                "/data-aggregation-vulnerable", "/data-aggregation-safe", "/internal_data.txt",
                                "/ssrf-vulnerable", "/ssrf-safe",
                                "/error", "/h2-console/**", "/uploads/**"
                        ).permitAll()
                        .requestMatchers(HttpMethod.POST,
                                "/xss-submit", "/xss-safe-submit",
                                "/sql-search-vulnerable", "/sql-search-safe-jpa", "/sql-search-safe-hql", "/sql-search-safe-sp",
                                "/upload-file-vulnerable", "/upload-file-safe",
                                "/update-email-vulnerable", "/update-profile-name-vulnerable", "/update-email", "/update-profile-name",
                                "/data-aggregation-search", "/data-aggregation-search-safe"
                        ).permitAll()
                        .requestMatchers(HttpMethod.POST, "/ssrf-read-file").authenticated()
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/viewer/**").hasAnyRole("VIEWER", "USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST,
                                "/update-email-protected-spring",
                                "/update-profile-name-protected-spring"
                        ).authenticated()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                );

        http.csrf(csrf -> csrf.disable());

        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

        return http.build();
    }
}