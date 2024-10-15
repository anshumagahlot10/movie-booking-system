package com.mbs.movie_booking.security.service;

import org.springframework.http.ResponseEntity;

import com.mbs.movie_booking.security.dto.LoginRequest;
import com.mbs.movie_booking.security.dto.LoginResponse;

public interface AuthService {
  ResponseEntity<LoginResponse> login(LoginRequest loginRequest, String accessToken, String refreshToken);

  ResponseEntity<LoginResponse> logout(String accessToken, String refreshToken);

  ResponseEntity<LoginResponse> refresh(String refreshToken);



}
