package com.pabloagustin.bookingsystem.authentication;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtService {

	private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

	@Value("${booking.app.SECRET_KEY}")
	private String SECRET_KEY;

	public String generateJwtToken(Authentication authentication){

		UserDetailsImplementation userPrincipal = (UserDetailsImplementation) authentication.getPrincipal();

		return Jwts.builder()
				.setSubject(userPrincipal.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
				.signWith(key(), SignatureAlgorithm.HS256)
				.compact();
	}

	private Key key(){
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
	}

	public boolean validateJwtToken(String authToken){
		try {
			Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
			return true;
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty: {}", e.getMessage());
		}

		return false;
	}

	public String getUsernameFromJwtToken(String token){
		return Jwts.parserBuilder().setSigningKey(key()).build()
				.parseClaimsJws(token).getBody().getSubject();
	}
}
