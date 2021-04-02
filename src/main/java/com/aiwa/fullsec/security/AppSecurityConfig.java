package com.aiwa.fullsec.security;

import com.aiwa.fullsec.security.auth.AppUserDetailsService;
import com.aiwa.fullsec.security.jwt.JwtTokenVerifier;
import com.aiwa.fullsec.security.jwt.JwtUserAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.aiwa.fullsec.security.ApplicationUserPermissions.COURSE_WRITE;
import static com.aiwa.fullsec.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {
/*
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AppSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
 */

    private final AppUserDetailsService mAppUserDetailsService;
    private final PasswordEncoder mPasswordEncoder;

    @Autowired
    public AppSecurityConfig(AppUserDetailsService appUserDetailsService, PasswordEncoder passwordEncoder) {
        mAppUserDetailsService = appUserDetailsService;
        mPasswordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUserAuthenticationFilter(authenticationManager()))
                .addFilterAfter(new JwtTokenVerifier(), JwtUserAuthenticationFilter.class)
                .authorizeRequests()
                .mvcMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .mvcMatchers("/api/**").hasRole(STUDENT.name())
                .mvcMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .mvcMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .mvcMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .mvcMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), TRAINEE.name())
                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                    .usernameParameter("username") // name parameter into form fields
//                    .passwordParameter("password")
//                    .defaultSuccessUrl("/courses", true)
//                    .permitAll()
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("secure key for remember me")
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me") // name parameter into form fields
//                    .logoutSuccessUrl("/login");
                ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(mPasswordEncoder);
        authProvider.setUserDetailsService(mAppUserDetailsService);
        return authProvider;
    }

/*
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails adaUser = User
                .builder()
                .username("ada")
                .password(passwordEncoder.encode("ada"))
//                .roles(STUDENT.name()) // ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails assaUser = User
                .builder()
                .username("assa")
                .password(passwordEncoder.encode("assa"))
//                .roles(ADMIN.name()) // ROLE_ADMINadd
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails haileUser = User
                .builder()
                .username("haile")
                .password(passwordEncoder.encode("haile"))
//                .roles(TRAINEE.name()) // ROLE_TRAINEE
                .authorities(TRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(adaUser, assaUser, haileUser);
    }
*/
}
