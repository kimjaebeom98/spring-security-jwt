package com.cos.jwt.config.auth;

import java.util.Collections;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwt.config.repository.UserRepository;
import com.cos.jwt.model.User;

import lombok.RequiredArgsConstructor;

// http:localhost:8080/login 요청이 올 때 동작을 안 함
// SpringConfig 에 formLogin을 disable 시켰으니 따라서 얘를 동작시킬수있도록 Filter를 만들어야함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	
	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
	
		return new PrincipalDetails(userEntity);
	}
}
