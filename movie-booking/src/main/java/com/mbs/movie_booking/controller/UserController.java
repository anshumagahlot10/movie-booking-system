package com.mbs.movie_booking.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mbs.movie_booking.dto.UserRegisterInfo;
import com.mbs.movie_booking.models.User;
import com.mbs.movie_booking.service.UserService;

import lombok.RequiredArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserRegisterInfo userRegister) {
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("messege", "User registered successfully" );
        userService.registerUser(
            userRegister.getName(),
            userRegister.getUsername(),
            userRegister.getPassword(), 
            userRegister.getEmail(),
            userRegister.getPhone());
        return ResponseEntity.ok(responseBody);
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUserDetails() {
        User user = userService.getCurrentlyLoggedInUser();
        return ResponseEntity.ok(user);
    }

}
