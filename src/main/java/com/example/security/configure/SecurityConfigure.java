package com.example.security.configure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfigure extends WebSecurityConfigurerAdapter {
	@Autowired
	UserDetailsService userDetailsService;


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.anyRequest().authenticated();
		http
			.formLogin()
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

		http
			.logout()
			.addLogoutHandler(new LogoutHandler() {
				@Override
				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
				}
			})
			.logoutSuccessHandler(new LogoutSuccessHandler() {
				@Override
				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
					throws IOException, ServletException {
					response.sendRedirect("/");
				}
			})
			.logoutUrl("/logout")
		;


		http.rememberMe()
			.rememberMeParameter("rember")			// 기본 파라미터는 remember-me
			.tokenValiditySeconds(3600)				// 기본은 14일 로 초 단위
			.userDetailsService(userDetailsService)
		;
	}
}
