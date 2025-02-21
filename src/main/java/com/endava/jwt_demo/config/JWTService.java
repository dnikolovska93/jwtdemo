package com.endava.jwt_demo.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JWTService {

    private static final String SECRET_KEY = "e0ebb776910ff8b3a208588660c77511c7de012b0c10d2b01ba0753b51f09e6a2b183f3223349b121be971b04d1f0bbe6e096dea3255142cb40f8489bcc8034507892af216e4df0148de0bddbe9e1c573aafcd2ac77683b683027c9f366ac56c04a40e02bb81996068e757b8e1f45df0a1a0a58c12bfa0c7c76c19ac524e41f82cc015b0ca90f462757f3174a5616a7ed37f8528f418b8ec215f2d3ee704473552668a962c1baf2d4e2d8eb7c509477cea86964327855c729b2e4fafe8d993dc9ad6ebef242d51e6eee156f1b092b7805c552b3fe1258334ab78d9d66fce79fb5f339a11ced00a2bcfa5552ffe9fd1888f0a22a49cbdc518d6d6eb26f801eb8e";

    public String getUserName(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigninKey()) // should i somehow set signing key?
                .compact();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = getUserName(token);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }


    private Claims extractAllClaims(String token) {
            return Jwts.parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
