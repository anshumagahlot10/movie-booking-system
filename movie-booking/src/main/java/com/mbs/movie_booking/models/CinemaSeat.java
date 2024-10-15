package com.mbs.movie_booking.models;

import com.mbs.movie_booking.enums.SeatType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "Cinema_Seat")
public class CinemaSeat {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int cinemaSeatID;

    @Column(nullable = false)
    private int seatNumber;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SeatType type;

    @ManyToOne
    @JoinColumn(name = "cinemaHallID", nullable = false)
    private CinemaHall cinemaHall;
}
