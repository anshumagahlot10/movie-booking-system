package com.mbs.movie_booking.service;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mbs.movie_booking.models.User;
import com.mbs.movie_booking.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void registerUser(String name,String username,String password,String email,String phone) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("User already exists");
        }
        
        User user = User.builder()
                .name(name)
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .phone(phone)
                .build();

        userRepository.save(user);
    }
}
