package com.example.security.controller;

import com.example.security.domain.Account;
import com.example.security.domain.AccountDto;
import com.example.security.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class UserController {

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@GetMapping("/mypage")
	public String myPage () {
		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser () {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser (AccountDto accountDto) {
		ModelMapper modelMapper = new ModelMapper();

		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));

		userService.createUser(account);

		return "redirect:/";
	}
}
