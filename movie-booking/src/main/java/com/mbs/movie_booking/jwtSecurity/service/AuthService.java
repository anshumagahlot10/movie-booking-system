package com.mbs.movie_booking.jwtSecurity.service;

import org.springframework.http.ResponseEntity;

import com.mbs.movie_booking.dto.LoginRequest;
import com.mbs.movie_booking.dto.LoginResponse;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

  ResponseEntity<LoginResponse> login(LoginRequest loginRequest);

  ResponseEntity<LoginResponse> logout(HttpServletRequest request);

  ResponseEntity<LoginResponse> refresh(String refreshToken);

}
