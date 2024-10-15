package com.mbs.movie_booking.models;

import java.math.BigDecimal;

import com.mbs.movie_booking.enums.SeatStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ShowSeat {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int showSeatID;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SeatStatus status;

    @Column(nullable = false)
    private BigDecimal price;

    @ManyToOne
    @JoinColumn(name = "cinemaSeatID", nullable = false)
    private CinemaSeat cinemaSeat;

    @ManyToOne
    @JoinColumn(name = "showID", nullable = false)
    private Show show;

    @ManyToOne
    @JoinColumn(name = "bookingID", nullable = false)
    private Booking booking;
}
