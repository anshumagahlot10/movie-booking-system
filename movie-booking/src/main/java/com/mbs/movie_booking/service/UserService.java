package com.mbs.movie_booking.service;

import com.mbs.movie_booking.dto.UserRegisterInfo;
import com.mbs.movie_booking.models.User;

public interface UserService {

    void registerUser(UserRegisterInfo userRegisterInfo);

    public User getCurrentlyLoggedInUser();
}
