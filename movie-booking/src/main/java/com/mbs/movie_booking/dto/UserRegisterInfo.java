package com.mbs.movie_booking.dto;

import lombok.Data;

@Data
public class UserRegisterInfo {
    private String name;
    private String username;
    private String password;
    private String email;
    private String phone;
}
