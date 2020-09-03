package com.example.security.service.impl;

import com.example.security.domain.Account;
import com.example.security.repository.UserRepository;
import com.example.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service("userService")
public class UserServiceImpl implements UserService {
	@Autowired
	private UserRepository userRepository;

	@Override
	public void createUser(Account account) {
		userRepository.save(account);
	}
}
