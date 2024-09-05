package com.emreaknci.auth.api.service;

import com.emreaknci.auth.api.dto.RefreshRequest;
import com.emreaknci.auth.api.dto.RegisterRequest;
import com.emreaknci.auth.api.dto.LoginRequest;
import com.emreaknci.auth.api.dto.LoginResponse;
import com.emreaknci.auth.api.exception.EmailAlreadyExistsException;
import com.emreaknci.auth.api.exception.RefreshTokenExpiredException;
import com.emreaknci.auth.api.exception.RefreshTokenNotFoundException;
import com.emreaknci.auth.api.exception.UsernameAlreadyExistsException;
import com.emreaknci.auth.api.model.User;
import com.emreaknci.auth.api.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

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

        return getLoginResponse(user);
    }

    public LoginResponse refreshToken(RefreshRequest refreshRequest) {
        User user = userRepository.findByRefreshToken(refreshRequest.refreshToken())
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));

        if(user.getRefreshTokenExpiryDate().before(new Date()))
            throw new RefreshTokenExpiredException("The user's refresh token has expired.");

        return getLoginResponse(user);
    }

    private LoginResponse getLoginResponse(User user) {
        var accessToken = jwtService.generateAccessToken(user);
        var newRefreshToken = jwtService.generateRefreshToken(user);
        user.setRefreshToken(newRefreshToken.getToken());
        user.setRefreshTokenExpiryDate(newRefreshToken.getExpirationTime());
        userRepository.save(user);
        return new LoginResponse(accessToken.getToken(), newRefreshToken.getToken());
    }
}
