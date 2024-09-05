package com.emreaknci.auth.api.service;


import com.emreaknci.auth.api.dto.TokenResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.key}")
    private String SECRET_KEY;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${refresh-token.expiration}")
    private long refreshTokenExpiration;

    public String findUsername(String token) {
        return exportToken(token, Claims::getSubject);
    }

    private <T> T exportToken(String token, Function<Claims, T> claimsTFunction) {
        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build().parseClaimsJws(token).getBody();

        return claimsTFunction.apply(claims);
    }

    private Key getKey() {
        byte[] key = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(key);
    }

    public boolean tokenControl(String jwt, UserDetails userDetails) {
        final String username = findUsername(jwt);
        return (username.equals(userDetails.getUsername()) && !exportToken(jwt, Claims::getExpiration).before(new Date()));
    }

    public TokenResponse generateAccessToken(UserDetails user) {
        return buildToken(user, jwtExpiration);
    }

    public TokenResponse generateRefreshToken(UserDetails user) {
        return buildToken(user, refreshTokenExpiration);
    }

    private TokenResponse buildToken(UserDetails user, long expiration) {
        var expTime= new Date(System.currentTimeMillis() + expiration);
        var token=Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expTime)
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();

        return new TokenResponse(token, expTime);

    }
}
