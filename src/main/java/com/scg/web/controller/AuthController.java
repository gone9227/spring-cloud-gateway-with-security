package com.scg.web.controller;

import com.scg.web.model.auth.LoginDto;
import com.scg.web.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
@RestController
public class AuthController {

    private final AuthService authService;

    @PostMapping("/auth/login")
    public Mono<ResponseEntity<?>> login(@RequestBody LoginDto loginDto){
        log.debug("Login DTO ====>  {}", loginDto);
        return Mono.just(ResponseEntity.ok(authService.login(loginDto)));
    }

    @GetMapping("/test")
    public String test(){
        return "test";
    }

}
