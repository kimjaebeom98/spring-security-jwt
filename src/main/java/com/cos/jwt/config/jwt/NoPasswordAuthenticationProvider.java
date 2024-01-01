package com.cos.jwt.config.jwt;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import com.cos.jwt.config.auth.PrincipalDetailsService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class NoPasswordAuthenticationProvider implements AuthenticationProvider{
	
	private final PrincipalDetailsService principalDetailsService;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		System.out.println("커스텀프로바이더 테스트");
		String username = authentication.getName();
		UserDetails userDetails = principalDetailsService.loadUserByUsername(username);
		return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
