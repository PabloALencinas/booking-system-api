package com.pabloagustin.bookingsystem.config;


import com.pabloagustin.bookingsystem.authentication.AuthEntryPoint;
import com.pabloagustin.bookingsystem.authentication.AuthTokenFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig implements WebMvcConfigurer {

	private final UserDetailsService userDetailsService;
	private final AuthEntryPoint authEntryPoint;
	private final AuthTokenFilter authTokenFilter;

	@Bean
	public DaoAuthenticationProvider authenticationProvider(){
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}

	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception{
		return  authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http.csrf(csrf -> csrf.disable())
				.exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPoint))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth ->
						auth.requestMatchers("/api/auth/**",
										"/api/movie/**",
										"/api/cinemaroom/**",
										"/api/reservation/**")
								.permitAll()
								.requestMatchers("/api/test/**", "/public/**").permitAll()
								.anyRequest().authenticated()
				);

		http.authenticationProvider(authenticationProvider());
		http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**") // Esto permite el acceso desde cualquier origen
				.allowedMethods("GET", "POST", "PUT", "DELETE")
				.allowedHeaders("*");
	}
}
