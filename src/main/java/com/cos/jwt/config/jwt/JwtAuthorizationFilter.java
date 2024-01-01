package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.security.Key;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.config.repository.UserRepository;
import com.cos.jwt.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

// 시큐리티가 filter들을 가지고 있는데 그 필터 중에 BasicAuthenticationFilter 라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 됨
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안 탐
// 즉 /api/v1/user/**, /api/v1/admin/** 등등은 인증 체크하고 접속 허가를 받을려고 무조건 이 필터를 타고
// 아니면 /login, /join같은 것은 jwtAuthentcationFilter를 탐 왜냐하면 인증해야하니께
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

	private Key key;
	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, @Value("${jwt.secret}") String secret, UserRepository userRepository) {
		super(authenticationManager);
		byte[] keyBytes = Decoders.BASE64.decode(secret);
	    this.key = Keys.hmacShaKeyFor(keyBytes);
	    this.userRepository = userRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("인증이나 권한이 필요한 주소로 요청이 옴");
		
		// Header에 Authorization에 bearer + jwtToken 값을 넣어줌
		String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
		System.out.println("jwtHeader : " + jwtHeader);
		// "/join" 요청에 대한 예외 처리
	    if (request.getRequestURI().equals("/join")) {
	        chain.doFilter(request, response);
	        return;
	    }
		// header가 있는지 확인
		if(jwtHeader == null && !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response); 
			return; // doFilter를 했지만 return 했으므로 진행 안되도록 함 
		}
		
		
		
		
		// jwtToken을 검증을 해서 정상적인 사용자인지 확인
		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, ""); // prefix인 Bearer를 제거하고 jwt 토큰 값만
		Claims claims = Jwts.parserBuilder()
	            .setSigningKey(key)
	            .build()
	            .parseClaimsJws(jwtToken)
	            .getBody();
		String username = (String) claims.get("username");
		System.out.println("요청된 jwtToken의 claim으로 부터 받아온 username : " + username);
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			// jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다.
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			// 강제로 시큐리티의 세션(SecurityContextHolder)에 접근하여 Authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
		
	}

}
