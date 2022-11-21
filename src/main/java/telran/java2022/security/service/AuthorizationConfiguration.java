package telran.java2022.security.service;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthorizationConfiguration {

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic();// Basic authentication
		http.csrf().disable();// No only get request
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);// don`t save session

		http.authorizeRequests(
				authorize -> authorize
				.mvcMatchers("/account/register", "/forum/posts/**").permitAll()// From this url(any method) allow all
				.mvcMatchers("/account/user/password").authenticated()
				.mvcMatchers("/account/user/*/role/*/**").access("@customPassSecurity.checkPass(authentication.name) and hasRole('ADMINISTRATOR')")
				.mvcMatchers(HttpMethod.POST,"/account/login").access("@customPassSecurity.checkPass(authentication.name)")
				.mvcMatchers(HttpMethod.PUT, "/account/user/{login}").access("#login == authentication.name and @customPassSecurity.checkPass(authentication.name)")
				.mvcMatchers(HttpMethod.DELETE, "/account/user/{login}").access("@customPassSecurity.checkPass(authentication.name) and #login == authentication.name or hasAnyRole('ADMINISTRATOR', 'USER')")
				.mvcMatchers(HttpMethod.POST, "/forum/post/{author}").access("#author ==authentication.name and @customPassSecurity.checkPass(authentication.name)")
				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}").access("#author ==authentication.name and @customPassSecurity.checkPass(authentication.name)")
				.mvcMatchers(HttpMethod.DELETE, "/forum/post/{id}").access("(@customSecurity.checkPostAuthor(#id, authentication.name) or hasRole('MODERATOR')) and @customPassSecurity.checkPass(authentication.name)")
				.mvcMatchers( "/forum/post/{id}").access("@customPassSecurity.checkPass(authentication.name) and @customSecurity.checkPostAuthor(#id, authentication.name)")
				.anyRequest().authenticated()// Any request require authentication
				
				
//				.mvcMatchers("/account/register/**", "/forum/posts/**").permitAll()// From this url(any method) allow all
//				.mvcMatchers("/account/user/password/**").authenticated()
//				.mvcMatchers("/account/user/*/role/*/**").hasRole("ADMINISTRATOR")
//				.mvcMatchers(HttpMethod.PUT, "/account/user/{login}/**").access("#login == authentication.name")
//				.mvcMatchers(HttpMethod.DELETE, "/account/user/{login}/**").access("#login == authentication.name or hasRole('ADMINISTRATOR')")
//				.mvcMatchers(HttpMethod.POST, "/forum/post/{author}/**").access("#author ==authentication.name")
//				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}/**").access("#author ==authentication.name")
//				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/like/**").authenticated()
//				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/**").access("@customSecurity.checkPostAuthor(#id, authentication.name)")				
//				.mvcMatchers(HttpMethod.DELETE, "/forum/post/{id}/**").access("@customSecurity.checkPostAuthor(#id, authentication.name) or hasRole('MODERATOR')")
//				.anyRequest().authenticated()// Any request require authentication
		);
		return http.build();
	}

}
