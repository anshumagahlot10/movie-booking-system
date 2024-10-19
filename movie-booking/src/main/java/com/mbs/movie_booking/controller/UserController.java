package com.mbs.movie_booking.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mbs.movie_booking.dto.UserRegisterInfo;
import com.mbs.movie_booking.models.User;
import com.mbs.movie_booking.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody UserRegisterInfo userRegister) {

        System.out.println(userRegister);
        userService.registerUser(userRegister);
        return new ResponseEntity<String>(HttpStatus.CREATED);
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUserDetails() {
        User user = userService.getCurrentlyLoggedInUser();
        return ResponseEntity.ok(user);
    }

}
