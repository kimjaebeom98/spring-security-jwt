package com.cos.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;


// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter(로그인을 진행하는 필터)가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter가 동작함 
// 근데 formLogin을 disable 시켰기 때문에 filter를 addFilter로 등록해야함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	private AuthenticationManager authenticationManager;
	
	private Key key;
	
	
	public JwtAuthenticationFilter(AuthenticationManager authenticationManager, @Value("${jwt.secret}") String secret) {
	    byte[] keyBytes = Decoders.BASE64.decode(secret);
	    this.key = Keys.hmacShaKeyFor(keyBytes);
	    this.authenticationManager = authenticationManager;
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
		// 1. username, password 받고
		try {
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println(input);
//			}
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// 2. 정상인지 로그인 시도 -> authenticationManager가 로그인 시도
			// 그러면 PrincipalDetailsService가 호출돼서 loadUserByUsername() 함수 실행 
			// 정상이면 authentication이 리턴되고 DB에 있는 username과 password가 일치
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			//  로그인이 된 거 체크
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println(principalDetails.getUser().getUsername());
			
			// return authentication; 3. PrincipalDetails를 세션에 담는  << 로그인이 되었다는 듯
			// 권한 관리를 security가 대신 해줌
			// jwt 토큰을 사용하면서 세션을 만들 필요는 없지만 단지 권한 처리 때문에 session에 넣어 줌
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 아래 함수가 실행
	// jwt 토큰을 만들어서 request 요청한 사용자에게 jwt 토큰을 response해 줌
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("인증 완료됨");
		
		//Authentication에 있는 정보로 JWT Token 생성해서 response에 담아주기
		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();
		
		// JWT 토큰 생성
	    String jwtToken = Jwts.builder()
	            .setSubject(principalDetailis.getUsername())
	            .setExpiration(new Date(System.currentTimeMillis() + (60000*30))) // 만료시간 : 현재시간 + 30분
	            .claim("username", principalDetailis.getUsername())
	            .claim("authorities", principalDetailis.getAuthorities())
	            .signWith(key, SignatureAlgorithm.HS512)
	            .compact();
	    // jwtToken을 jwt.io에서 암, 복호화 해보면 정보가 보임
	    System.out.println(jwtToken);
	    // JWT 토큰을 응답 헤더에 추가
	    response.addHeader("Authorization", "Bearer " + jwtToken);
		
	}
	// BytesKeyGenerator를 사용하여 임의의 키를 생성하고, Keys.hmacShaKeyFor를 통해 Key 객체로 변환합니다.
//	private Key getSecretKey() {
//		System.out.println("secretKey : " + key);
//		BytesKeyGenerator keyGenerator = KeyGenerators.shared(64);
//        byte[] keyBytes = keyGenerator.generateKey();
//        return Keys.hmacShaKeyFor(keyBytes);
//    }

	
}
