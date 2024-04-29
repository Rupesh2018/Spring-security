package com.dncoyote.springsecurity.service;

import com.dncoyote.springsecurity.dto.SignUpRequest;
import com.dncoyote.springsecurity.entity.User;

public interface AuthenticationService {
    public User signUp(SignUpRequest signUpRequest);
}
