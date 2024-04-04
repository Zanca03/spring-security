package dev.carlosezpereira.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static dev.carlosezpereira.springsecurity.security.ApplicationUserPermission.COURSE_WRITE;
import static dev.carlosezpereira.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "INDEX", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .antMatchers(HttpMethod.DELETE,"/managment/api/**").hasAnyAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.POST,"/managment/api/**").hasAnyAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.PUT,"/managment/api/**").hasAnyAuthority(COURSE_WRITE.name())
                .antMatchers(HttpMethod.GET,"/managment/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails usuarioComum = User.builder()
                .username("Carlos")
                .password(passwordEncoder.encode("coxinha123"))
                .roles(STUDENT.name()) //ROLE_STUDENT
                .build();
        UserDetails usuarioAdm = User.builder()
                .username("Admin")
                .password(passwordEncoder.encode("root"))
                .roles(ADMIN.name()) //ROLE_ADMIN
                .build();
        UserDetails usuarioAdmTrainee = User.builder()
                .username("AdminTrainee")
                .password(passwordEncoder.encode("root"))
                .roles(ADMINTRAINEE.name()) //ROLE_ADMIN
                .build();
        return new InMemoryUserDetailsManager(
                usuarioComum,
                usuarioAdm,
                usuarioAdmTrainee
        );
    }
}
