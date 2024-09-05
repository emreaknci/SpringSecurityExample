package com.emreaknci.auth.api.service;

import com.emreaknci.auth.api.dto.RegisterRequest;
import com.emreaknci.auth.api.dto.LoginRequest;
import com.emreaknci.auth.api.dto.LoginResponse;
import com.emreaknci.auth.api.exception.EmailAlreadyExistsException;
import com.emreaknci.auth.api.exception.UsernameAlreadyExistsException;
import com.emreaknci.auth.api.model.User;
import com.emreaknci.auth.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public boolean register(RegisterRequest registerRequest) {

        boolean checkUsernameExist = userRepository.findByUsername(registerRequest.username()).isPresent();
        if (checkUsernameExist)
            throw new UsernameAlreadyExistsException("This username is already in use");

        boolean checkEmailExist = userRepository.findByEmail(registerRequest.email()).isPresent();
        if (checkEmailExist)
            throw new EmailAlreadyExistsException("This email is already in use");

        User user = User.builder()
                .username(registerRequest.username())
                .email(registerRequest.email())
                .password(passwordEncoder.encode(registerRequest.password()))
                .authorities(registerRequest.authorities()).build();

        userRepository.save(user);
        return true;
    }

    public LoginResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByUsernameOrEmail(loginRequest.usernameOrEmail(), loginRequest.usernameOrEmail())
                .orElseThrow();

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.usernameOrEmail(), loginRequest.password()));

        String token = jwtService.generateToken(user);
        return new LoginResponse(token);
    }
}
