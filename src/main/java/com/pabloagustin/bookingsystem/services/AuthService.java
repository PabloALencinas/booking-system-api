package com.pabloagustin.bookingsystem.services;

import com.pabloagustin.bookingsystem.authentication.JwtService;
import com.pabloagustin.bookingsystem.authentication.UserDetailsImplementation;
import com.pabloagustin.bookingsystem.models.ERole;
import com.pabloagustin.bookingsystem.models.Role;
import com.pabloagustin.bookingsystem.models.User;
import com.pabloagustin.bookingsystem.payloads.JwtResponse;
import com.pabloagustin.bookingsystem.payloads.LoginRequest;
import com.pabloagustin.bookingsystem.payloads.MessageResponse;
import com.pabloagustin.bookingsystem.payloads.SignupRequest;
import com.pabloagustin.bookingsystem.repositories.RoleRepository;
import com.pabloagustin.bookingsystem.repositories.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthService authService;

	// Login User
	public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest){
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(),
						loginRequest.getPassword())
		);

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtService.generateJwtToken(authentication);

		UserDetailsImplementation userDetails = (UserDetailsImplementation) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(new JwtResponse
				(jwt,
						userDetails.getId(),
						userDetails.getUsername(),
						userDetails.getEmail(),
						roles)
		);
	}

	// SignUp User
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest){

		if (userRepository.existsByEmail(signupRequest.getUsername())){
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username already taken"));
		}

		if (userRepository.existsByEmail(signupRequest.getEmail())){
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use"));
		}

		// Creating new user's account
		User user = new User(signupRequest.getUsername(),
				signupRequest.getEmail(),
				passwordEncoder.encode(signupRequest.getPassword())
		);

		Set<String> strRoles = signupRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if(strRoles == null){
			Role userRole = roleRepository.findByName(ERole.USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found"));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				if (role.equals("admin")) {
					Role adminRole = roleRepository.findByName(ERole.ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found"));
					roles.add(adminRole);
				} else {
					Role userRole = roleRepository.findByName(ERole.USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully"));

	}


}
