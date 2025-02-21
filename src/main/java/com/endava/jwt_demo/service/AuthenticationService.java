package com.endava.jwt_demo.service;

import com.endava.jwt_demo.config.JWTService;
import com.endava.jwt_demo.controller.AuthenticationRequest;
import com.endava.jwt_demo.controller.AuthenticationResponse;
import com.endava.jwt_demo.controller.RegisterRequest;
import com.endava.jwt_demo.domain.SecurityUser;
import com.endava.jwt_demo.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JWTService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserServiceImplementation userServiceImplementation;

    public AuthenticationResponse register(RegisterRequest request) {
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        User user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .role(request.getRole())
                .password(encodedPassword)
                .build();
        userServiceImplementation.saveUser(user);
        String token = jwtService.generateToken(new SecurityUser(user));
        return AuthenticationResponse.builder()
                .accessToken(token)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
        ));
        SecurityUser user = userServiceImplementation.loadUserByUserName(request.getEmail());
        String token = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(token)
                .build();
    }
}
