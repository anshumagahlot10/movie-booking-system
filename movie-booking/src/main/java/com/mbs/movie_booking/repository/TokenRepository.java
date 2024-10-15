package com.mbs.movie_booking.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import com.mbs.movie_booking.enums.TokenType;
import com.mbs.movie_booking.models.Token;

public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByValue(String token);
    @Modifying
    @Transactional
    @Query("DELETE FROM Token t WHERE t.user.username = ?1 AND t.type = ?2")
    void deleteAccessTokenByUsername(String username, TokenType type);
}

