package com.scg.web.service;

import com.scg.config.auth.token.CustomAuthenticationToken;
import com.scg.web.model.auth.LoginDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final ReactiveAuthenticationManager authenticationManager;

    public Mono<Authentication> login(LoginDto loginDto){
        Authentication authentication = new CustomAuthenticationToken(loginDto.getUserId(), loginDto.getPassword());
        return authenticationManager.authenticate(authentication);
    }
}
