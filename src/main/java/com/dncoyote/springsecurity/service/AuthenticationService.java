package com.dncoyote.springsecurity.service;

import com.dncoyote.springsecurity.auth.AuthenticationRequest;
import com.dncoyote.springsecurity.dto.SignUpRequest;
import com.dncoyote.springsecurity.user.User;

public interface AuthenticationService {
    public User signUp(SignUpRequest signUpRequest);

    public Object authenticate(AuthenticationRequest request);
}
