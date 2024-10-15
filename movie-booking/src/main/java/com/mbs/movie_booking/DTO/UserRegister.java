package com.mbs.movie_booking.DTO;

import lombok.Data;

@Data
public class UserRegister {
    private String name;
    private String username;
    private String password;
    private String email;
    private String phone;
}
