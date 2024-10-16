package com.mbs.movie_booking.security.service.Impl;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.mbs.movie_booking.enums.TokenType;
import com.mbs.movie_booking.models.Token;
import com.mbs.movie_booking.models.User;
import com.mbs.movie_booking.repository.TokenRepository;
import com.mbs.movie_booking.repository.UserRepository;
import com.mbs.movie_booking.security.dto.LoginRequest;
import com.mbs.movie_booking.security.dto.LoginResponse;
import com.mbs.movie_booking.security.exception.AppException;
import com.mbs.movie_booking.security.exception.ResourceNotFoundException;
import com.mbs.movie_booking.security.jwt.JwtTokenProvider;
import com.mbs.movie_booking.security.service.AuthService;
import com.mbs.movie_booking.security.util.CookieUtil;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    @Value("${JWT_ACCESS_TOKEN_DURATION_MINUTE}")
    private long accessTokenDurationMinute;
    @Value("${JWT_ACCESS_TOKEN_DURATION_SECOND}")
    private long accessTokenDurationSecond;
    @Value("${JWT_REFRESH_TOKEN_DURATION_DAY}")
    private long refreshTokenDurationDay;
    @Value("${JWT_REFRESH_TOKEN_DURATION_SECOND}")
    private long refreshTokenDurationSecond;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtTokenProvider tokenProvider;
    private final CookieUtil cookieUtil;
    private final AuthenticationManager authenticationManager;

    @Override
    public ResponseEntity<LoginResponse> login(LoginRequest loginRequest, String accessToken, String refreshToken) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.email(), loginRequest.password()));

        String email = loginRequest.email();

        User user = userRepository.findByEmail(email).orElseThrow(
                () -> new ResourceNotFoundException("User not found"));

        boolean accessTokenValid = tokenProvider.validateToken(accessToken);
        boolean refreshTokenValid = tokenProvider.validateToken(refreshToken);

        HttpHeaders responseHeaders = new HttpHeaders(); // Prepares headers to send back the tokens in cookies.
        Token newAccessToken = null;
        Token newRefreshToken = null;

        revokeAllTokenOfUser(user);

        if (!accessTokenValid && !refreshTokenValid) {
            newAccessToken = tokenProvider.generateAccessToken(
                    Map.of("role", "ROLE_USER"),
                    accessTokenDurationMinute,
                    ChronoUnit.MINUTES,
                    user);

            newRefreshToken = tokenProvider.generateRefreshToken(
                    refreshTokenDurationDay,
                    ChronoUnit.DAYS,
                    user);

            newAccessToken.setUser(user);
            newRefreshToken.setUser(user);

            // save tokens in db
            tokenRepository.saveAll(List.of(newAccessToken, newRefreshToken));

            addAccessTokenCookie(responseHeaders, newAccessToken);
            addRefreshTokenCookie(responseHeaders, newRefreshToken);
        }

        if (!accessTokenValid && refreshTokenValid) {
            newAccessToken = tokenProvider.generateAccessToken(
                    Map.of("role", "ROLE_USER"),
                    accessTokenDurationMinute,
                    ChronoUnit.MINUTES,
                    user);

            addAccessTokenCookie(responseHeaders, newAccessToken);
        }

        if (accessTokenValid && refreshTokenValid) {
            newAccessToken = tokenProvider.generateAccessToken(
                    Map.of("role", "ROLE_USER"),
                    accessTokenDurationMinute,
                    ChronoUnit.MINUTES,
                    user);

            newRefreshToken = tokenProvider.generateRefreshToken(
                    refreshTokenDurationDay,
                    ChronoUnit.DAYS,
                    user);

            newAccessToken.setUser(user);
            newRefreshToken.setUser(user);

            // save tokens in db
            tokenRepository.saveAll(List.of(newAccessToken, newRefreshToken));

            addAccessTokenCookie(responseHeaders, newAccessToken);
            addRefreshTokenCookie(responseHeaders, newRefreshToken);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        // System.out.println(SecurityContextHolder.getContext().getAuthentication());

        LoginResponse loginResponse = new LoginResponse(true, "ROLE_USER");
        // System.out.println("access token:" + newAccessToken + "refresh token" + newRefreshToken);

        return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);
    }

    @Override
    public ResponseEntity<LoginResponse> refresh(String refreshToken) {
        boolean refreshTokenValid = tokenProvider.validateToken(refreshToken);

        if (!refreshTokenValid)
            throw new AppException(HttpStatus.BAD_REQUEST, "Refresh token is invalid");

        String username = tokenProvider.getUsernameFromToken(refreshToken);
        User user = userRepository.findByEmail(username).orElseThrow(
                () -> new ResourceNotFoundException("User not found"));
        tokenRepository.deleteAccessTokenByUsername(username, TokenType.ACCESS); 

        Token newAccessToken = tokenProvider.generateAccessToken(
                Map.of("role", "ROLE_USER"),
                accessTokenDurationMinute,
                ChronoUnit.MINUTES,
                user);
        newAccessToken.setUser(user);
        tokenRepository.save(newAccessToken);
        
        HttpHeaders responseHeaders = new HttpHeaders();
        addAccessTokenCookie(responseHeaders, newAccessToken);
       
        LoginResponse loginResponse = new LoginResponse(true, "ROLE_USER");
        // System.out.println("new access token:" + newAccessToken + "refresh token" + refreshToken);

        return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);
    }

    @Override
    public ResponseEntity<LoginResponse> logout(String accessToken, String refreshToken) {

        SecurityContextHolder.clearContext();

        String username = tokenProvider.getUsernameFromToken(accessToken);
        User user = userRepository.findByEmail(username).orElseThrow(
                () -> new ResourceNotFoundException("User not found"));

        Token access_token = tokenRepository.findByValue(accessToken).orElseThrow(
                () -> new ResourceNotFoundException("Access Token not found"));

        Token refresh_token = tokenRepository.findByValue(refreshToken).orElseThrow(
                () -> new ResourceNotFoundException("Refresh Token not found"));
        revokeAllTokenOfUser(user);

        HttpHeaders responseHeaders = new HttpHeaders();

        responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.deleteAccessTokenCookie().toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.deleteRefreshTokenCookie().toString());

        tokenRepository.delete(access_token);
        tokenRepository.delete(refresh_token);
        
        System.out.println("tokens deleted");

        LoginResponse loginResponse = new LoginResponse(false, null);

        System.out.println("logout successful");

        return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);

    }

    private void addAccessTokenCookie(HttpHeaders httpHeaders, Token token) {
        System.out.println("access token cookie caalled");
        httpHeaders.add(HttpHeaders.SET_COOKIE,
                cookieUtil.createAccessTokenCookie(token.getValue(), accessTokenDurationSecond).toString());
    }

    private void addRefreshTokenCookie(HttpHeaders httpHeaders, Token token) {
        System.out.println("refrsh token cookie caalled");
        httpHeaders.add(HttpHeaders.SET_COOKIE,
                cookieUtil.createRefreshTokenCookie(token.getValue(), refreshTokenDurationSecond).toString());
    }

    private void revokeAllTokenOfUser(User user) {
        // get all user tokens
        Set<Token> tokens = user.getTokens();

        tokens.forEach(token -> {
            if (token.getExpiryDate().isBefore(LocalDateTime.now()))
                tokenRepository.delete(token);
            else if (!token.isDisabled()) {
                token.setDisabled(true);
                tokenRepository.save(token);
            }
        });
    }

}
