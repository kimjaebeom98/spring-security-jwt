package com.cos.jwt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.auth.PrincipalDetailsService;
import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.config.jwt.NoPasswordAuthenticationProvider;
import com.cos.jwt.config.repository.UserRepository;


import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final CorsFilter corsFilter;
	private final PrincipalDetailsService principalDetailsService;
	private final UserRepository userRepository;
	
	@Value("${jwt.secret}")
    private String secretKey; // 프로퍼티 주입
	
	// 해당 메서드의 리턴되는 오브젝트를 loC로 등록
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		// MyFilter3는 시큐리티가 동작하기 전에 돌아야 하니깐 필터 체인 앞단에 위치하도록 함
		// 왜냐하면 MyFilter3가 컨트롤러 요청을 금지 시키니깐 잘못된 헤더의 Authorization이면
		// http.addFilterBefore(new MyFilter3(), UsernamePasswordAuthenticationFilter.class);
		http.csrf().disable();
		// 세션 사용 X
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.addFilter(corsFilter) // 사용자 인증이 필요없을 경우의 요청들은 @CrossOrigin을 컨트롤러에 붙이면 되는데, 인증이 필요한 시큐리티의 경우는 시큐리티 필터에 등록해야함
		.formLogin().disable() // form태그 만들어서 로그인 x
		.httpBasic().disable() // httpBasic이란 header의 Authorization 영역에 ID, PW를 담아서 요청할 때 마다 인증 가능하게 함 근데 http는 암호화가 안되니 https를 쓰긴함 
		                                  // 그럼 왜 disable 했냐면 Authorization영역에 우리는 token을 담을거임 id, pw보다는 token이 요청되는게 그나마 나아서 그런가..? 암튼 token을 달고 요청하는게 bearer 방식
		.apply(new MyCustomDsl())
		.and()
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.hasAnyRole("USER", "ADMIN", "MANAGER")
		.antMatchers("/api/v1/manager/**")
		.hasAnyRole("ADMIN", "MANAGER")
		.antMatchers("/api/v1/admin/**")
		.hasAnyRole("ADMIN")
		.anyRequest().permitAll();
		
		return http.build();
	}
	
	// 로그인 필터를 등록
	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
					.addFilter(new JwtAuthenticationFilter(authenticationManager, secretKey))
					.addFilter(new JwtAuthorizationFilter(authenticationManager, secretKey, userRepository));
		}
	}
	
	@Bean
    public AuthenticationProvider noPasswordAuthenticationProvider() {
        return new NoPasswordAuthenticationProvider(principalDetailsService);
    }
	
	@Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(noPasswordAuthenticationProvider());
    }
	
}
