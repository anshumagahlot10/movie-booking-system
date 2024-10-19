package com.mbs.movie_booking.dto;

public record LoginResponse( 
    boolean isLogged,
    String role
) {}
