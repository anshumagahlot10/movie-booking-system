package com.mbs.movie_booking;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import lombok.RequiredArgsConstructor;

@SpringBootApplication
@RequiredArgsConstructor
public class MovieBookingApplication{



	public static void main(String[] args) {
		SpringApplication.run(MovieBookingApplication.class, args);
	}

}
