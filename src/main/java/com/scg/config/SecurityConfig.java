package com.scg.config;

import com.scg.config.auth.userdetails.CustomUserDetailService;
import com.scg.jpa.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity      // WebFlux 기반 어플리케이션에서 Spring Security 사용하기 위한 annotation - WebFilter 에 의존함
public class SecurityConfig {

    // Spring Security WebFlux 는 SecurityWebFilterChain 타입의 Bean을 만들어서 시큐리티 설정을 한다.
    // RequestMatcher 별 Security 설정을 분리하고 싶은 경우, SecurityWebFilterChain 인스턴스를 여러개 설정할 수 있다.
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http
//                                                        , JwtTokenProvider jwtTokenProvider
                                                        , ReactiveAuthenticationManager reactiveAuthenticationManager) {

        return http
                .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
                        .authenticationEntryPoint((exchange, ex) ->
                                Mono.fromRunnable(() -> {
                                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                })
                        )
                        .accessDeniedHandler((exchange, denied) -> {
                            return Mono.fromRunnable(() -> {
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            });
                        }))
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(reactiveAuthenticationManager)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())       // Stateless 설정
                .authorizeExchange(exchange ->
                        exchange
                                // 인증,인가 허용/비허용 할 Uri, Method 설정
                                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                                .pathMatchers("/auth/login").permitAll()
                                .anyExchange().authenticated())
//                .addFilterAt(new JwtTokenAuthenticationFilter(jwtTokenProvider), SecurityWebFiltersOrder.HTTP_BASIC)
                .build();
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService(MemberRepository memberRepository) {
        return new CustomUserDetailService(memberRepository);
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService
                                                                    , PasswordEncoder passwordEncoder) {
        var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder);
        return authenticationManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
}
