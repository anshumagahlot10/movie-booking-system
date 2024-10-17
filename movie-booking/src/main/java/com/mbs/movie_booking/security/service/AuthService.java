package com.mbs.movie_booking.security.service;

import org.springframework.http.ResponseEntity;

import com.mbs.movie_booking.security.dto.LoginRequest;
import com.mbs.movie_booking.security.dto.LoginResponse;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {
  ResponseEntity<LoginResponse> login(LoginRequest loginRequest);

  ResponseEntity<LoginResponse> logout(HttpServletRequest request);

  ResponseEntity<LoginResponse> refresh(String refreshToken);



}
