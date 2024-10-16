package com.mbs.movie_booking.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mbs.movie_booking.models.User;
import com.mbs.movie_booking.security.dto.LoginRequest;
import com.mbs.movie_booking.security.dto.LoginResponse;
import com.mbs.movie_booking.security.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @CookieValue(name = "access_token", required = false) String accessToken,
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            @RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest, accessToken, refreshToken);
    }

    // @PostMapping("/refresh")
    // public ResponseEntity<LoginResponse> refreshToken(@CookieValue(name = "refresh_token", required = true) String refreshToken) {
    //     return authService.refresh(refreshToken);
    // }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(
        @RequestHeader(value = "Refresh-Token", required = true) String refreshToken) {
        return authService.refresh(refreshToken);
}

   
    // @PostMapping("/logout")
    // public ResponseEntity<LoginResponse> logout(
    //         @RequestHeader(name = "access_token", required = false) String accessToken,
    //         @RequestHeader(name = "refresh_token", required = false) String refreshToken) {
    //     return authService.logout(accessToken, refreshToken);
    // }

    @PostMapping("/logout")
    public ResponseEntity<LoginResponse> logout(HttpServletRequest request){
        return authService.logout(request); 
    }

    //  @PreAuthorize("isAuthenticated()")
    // @GetMapping("/info")
    // public ResponseEntity<UserLoggedDto> userLoggedInfo() {
    //     return ResponseEntity.ok(authService.getUserLoggedInfo());
    // }
}
