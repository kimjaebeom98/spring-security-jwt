package com.cos.jwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;


// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter(로그인을 진행하는 필터)가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함 
// 근데 formLogin을 disable 시켰기 때문에 filter를 addFilter로 등록해야함


public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	public JwtAuthenticationFilter(AuthenticationManager authenticationManger) {
		super(authenticationManger);
	}
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	// 1. username, password 받고
	// 2. 정상인지 로그인 시도 -> authenticationManager가 로그인 시도
	// 그러면 PrincipalDetailsService가 호출돼서 loadUserByUsername() 함수 실행 
	// 3. PrincipalDetails를 세션에 담고 << 세션에 담는 이유는 시큐리티가 권한관리를 하기 위해 (SecurityConfig의 .antMatchers("/api/v1/user/**") 	.hasAnyRole("USER", "ADMIN", "MANAGER") 이부분)
	// 4. jwt 토큰을 만들어서 응답해주면 됨
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		return super.attemptAuthentication(request, response);
	}
}
