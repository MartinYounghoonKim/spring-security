package com.example.security.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Data
public class Account {
	@Id
	@GeneratedValue(strategy = IDENTITY)
	private Long id;
	private String username;
	private String password;
	private String email;
	private String age;
	private String role;
}
