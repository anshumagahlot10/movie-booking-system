package com.mbs.movie_booking.security.exception;

import java.time.LocalDateTime;

public record ErrorDetails(
        LocalDateTime timestamp,
        int status,
        String error,
        String message,
        String details
){}
