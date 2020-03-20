package my.java.security.app.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static my.java.security.app.security.ApplicationUserRole.ADMIN;
import static my.java.security.app.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmith =
                User.builder()
                        .username("annasmith")
                        .password(passwordEncoder.encode("password"))
                        .roles(STUDENT.name()) // ROLE_STUDENT
                        .build();
        UserDetails lindaUser =
                User.builder()
                        .username("lindaUser")
                        .password(passwordEncoder.encode("password123"))
                        .roles(ADMIN.name()) // ROLE_ADMIN
                        .build();
        return new InMemoryUserDetailsManager(annaSmith, lindaUser);
    }
}
