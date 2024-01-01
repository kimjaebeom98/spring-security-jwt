package com.cos.jwt.config.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Long>{
	User findByUsername(String username);
}
