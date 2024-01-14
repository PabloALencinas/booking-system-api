package com.pabloagustin.bookingsystem.controllers;

import com.pabloagustin.bookingsystem.payloads.LoginRequest;
import com.pabloagustin.bookingsystem.payloads.SignupRequest;
import com.pabloagustin.bookingsystem.services.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	private final AuthService authService;

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){
		logger.info("User registered successfully: {}", signupRequest.getUsername());
		return authService.registerUser(signupRequest);
	}

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
		logger.info("User has beed loged successfully: {}", loginRequest.getUsername());
		return authService.login(loginRequest);
	}


}
