package com.cos.jwt.config.jwt;

public interface JwtProperties {
	int EXPIRATION_TIME = 60000*10; // 10일 (1/1000초)
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
