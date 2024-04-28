package com.dncoyote.springsecurity.service;

public interface JWTService {

    String extractUserName(String token);
    
    String generateToken(UserDetails userDetails);
   
    public boolean isTokenValid(String token, UserDetails userDetails);

}
