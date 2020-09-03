package com.example.security.configure;

import com.example.security.security.provider.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfigure extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		return new CustomAuthenticationProvider();
	}

	@Bean
	public PasswordEncoder passwordEncoder () {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http
			.authorizeRequests()
			.antMatchers("/", "/users").permitAll()
			.antMatchers("/mypage").hasRole("USER")
			.antMatchers("/messages").hasRole("MANAGER")
			.antMatchers("/config").hasRole("ADMIN")
			.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('MANAGER')")
			.anyRequest().authenticated()
		.and()
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/login_proc")
			.defaultSuccessUrl("/")
			.permitAll();

//		http.exceptionHandling()
//			.authenticationEntryPoint(new AuthenticationEntryPoint() {
//				@Override
//				public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
//					throws IOException, ServletException {
//					response.sendRedirect("/login");
//				}
//			})
//			.accessDeniedHandler(new AccessDeniedHandler() {
//				@Override
//				public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
//					throws IOException, ServletException {
//					response.sendRedirect("/denied");
//				}
//			})
//		http
//			.formLogin()
//			.loginPage("/loginPage") // 커스텀 로그인 페이지 (UI 화면)
//			.defaultSuccessUrl("/") // 성공시 이동할 페이지 링크
//			.failureUrl("/login") // 로그인 실패시 이동할 페이지 링크
//			.usernameParameter("userId")
//			.passwordParameter("passwd")
//			.loginProcessingUrl("/login_proc")
//			.successHandler(new AuthenticationSuccessHandler() { // 인증 성공 후, 추가로 로직을 구현할 경우
//				@Override
//				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//					System.out.println("authentication" + authentication.getName());
//					response.sendRedirect("/");
//				}
//			})
//			.failureHandler(new AuthenticationFailureHandler() { // 인증 실패 후, 추가로 로직을 구현할 경우
//				@Override
//				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//					System.out.println("exception" + exception.getMessage());
//				}
//			})
//			.permitAll() // 모든 사용자가 해당 URL 들은 접근 가능하도록 설정
		;

//		http
//			.logout()
//			.addLogoutHandler(new LogoutHandler() {
//				@Override
//				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//				}
//			})
//			.logoutSuccessHandler(new LogoutSuccessHandler() {
//				@Override
//				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
//					throws IOException, ServletException {
//					response.sendRedirect("/");
//				}
//			})
//			.logoutUrl("/logout")
//		;


//		http.rememberMe()
//			.rememberMeParameter("rember")			// 기본 파라미터는 remember-me
//			.tokenValiditySeconds(3600)				// 기본은 14일 로 초 단위
//			.userDetailsService(userDetailsService)
//		;

//		http
//			.sessionManagement()
//			.maximumSessions(1)
//			.maxSessionsPreventsLogin(true)
//		;
	}
}
