package my.java.security.app.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.validation.constraints.NotNull;

import static my.java.security.app.security.ApplicationUserPermission.COURSE_WRITE;
import static my.java.security.app.security.ApplicationUserRole.ADMIN;
import static my.java.security.app.security.ApplicationUserRole.ADMIN_TRAINEE;
import static my.java.security.app.security.ApplicationUserRole.STUDENT;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;
  private static final String URL = "/management/api/**";

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        // @formatter:off
        .csrf()
        .disable()
        .authorizeRequests()
        .antMatchers("/", "index", "css/*", "/js/*")
        .permitAll()
        .antMatchers("/api/**")
        .hasRole(STUDENT.name())
        .antMatchers(DELETE, URL)
        .hasAuthority(COURSE_WRITE.name())
        .antMatchers(POST, URL)
        .hasAuthority(COURSE_WRITE.name())
        .antMatchers(PUT, URL)
        .hasAuthority(COURSE_WRITE.name())
        .antMatchers(GET, URL)
        .hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
    // @formatter:on
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {
    UserDetails annaSmith =
        User.builder()
            .username("annasmith")
            .password(passwordEncoder.encode("password"))
            .authorities(STUDENT.grantedAuthority())
            // .roles(STUDENT.name()) // ROLE_STUDENT
            .build();
    UserDetails lindaUser =
        User.builder()
            .username("lindaUser")
            .password(passwordEncoder.encode("password123"))
            .authorities(ADMIN.grantedAuthority())
            //                        .roles(ADMIN.name()) // ROLE_ADMIN
            .build();
    UserDetails tomUser =
        User.builder()
            .username("tom")
            .password(passwordEncoder.encode("password123"))
            .authorities(ADMIN_TRAINEE.grantedAuthority())
            //                        .roles(ADMIN_TRAINEE.name()) // ROLE_ADMIN_TRAINEE
            .build();
    return new InMemoryUserDetailsManager(annaSmith, lindaUser, tomUser);
  }

  @Autowired
  public void configureGlobal(@NotNull AuthenticationManagerBuilder authenticationManagerBuilder)
      throws Exception {
    authenticationManagerBuilder
        .userDetailsService(userDetailsService())
        .passwordEncoder(new BCryptPasswordEncoder());
  }
}
