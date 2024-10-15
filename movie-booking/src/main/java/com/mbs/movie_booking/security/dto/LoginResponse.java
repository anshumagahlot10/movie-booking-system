package com.mbs.movie_booking.security.dto;


public record LoginResponse( 
    boolean isLogged,
    String role
) {}
