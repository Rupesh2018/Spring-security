package com.dncoyote.springsecurity.controller;

import java.io.IOException;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dncoyote.springsecurity.dto.SignUpRequest;
import com.dncoyote.springsecurity.service.AuthenticationService;
import com.dncoyote.springsecurity.user.User;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    private final AuthenticationService service;

    @PostMapping("/signup")
    public ResponseEntity<User> signup(
            @RequestBody SignUpRequest signUpRequest) {
        return ResponseEntity.ok(service.signUp(signUpRequest));
    }

    // @PostMapping("/authenticate")
    // public ResponseEntity<AuthenticationResponse> authenticate(
    //         @RequestBody AuthenticationRequest request) {
    //     return ResponseEntity.ok(service.authenticate(request));
    // }

    // @PostMapping("/refreshtoken")
    // public void refreshToken(
    //         HttpServletRequest request,
    //         HttpServletResponse response) throws IOException {
    //     service.refreshToken(request, response);
    // }

}
