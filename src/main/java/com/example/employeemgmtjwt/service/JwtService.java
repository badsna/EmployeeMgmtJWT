package com.example.employeemgmtjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
//to manipulated jwt token(generating one, extracting tokens, validating tokens) we add 3 dependencies

public class JwtService {
    //from https://allkeysgenerator.com/ >>Encryption key>>256-bits
    //for siging and verifying JWT token
    private static final String SECRET_KEY = "34743777217A25432A462D4A614E645267556B586E3272357538782F413F4428";

    //extract subject(here our subject is email from the token claims)
    public String extractUsername(String token) {
        return extractClam(token, Claims::getSubject);   //subject should be email so subject should be of jwt object
    }

    //to generate token with only userdetails
    public String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(), userDetails);
    }

    //to  generate token from extra claims
    public String generateToken(Map<String, Object> extraClaims,     //extra claims that we want to add
                                UserDetails userDetails  //pass employee details
    ) {

        return Jwts.builder().setClaims(extraClaims)
                //unique is email but for  spring its always username
                .setSubject(userDetails.getUsername())

                //when was token created
                .setIssuedAt(new Date(System.currentTimeMillis())).setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //valid for 24 hrs

                //which key we want to sign this token,signature algorithm
                .signWith(getSiginInKey(), SignatureAlgorithm.HS256).compact();         //generate and return the token
    }

    //to validate token
    //parameter cause we want to check if  the token belongs to the userdetails
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {

        //extracting expiration date from token and comaparing it with current date
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {

        return extractClam(token, Claims::getExpiration);
    }

    public <T> T extractClam(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()     //used to parse and verfiy the token
                .setSigningKey(getSiginInKey())  //sigining key is needed when we try to create to generate or to decode a token
                .build()
                .parseClaimsJws(token)//to verfiy  the token
                .getBody(); //retrive claims of the JWT token
    }

    private Key getSiginInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
