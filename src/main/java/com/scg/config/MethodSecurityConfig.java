//package com.scg.config;
//
//import com.scg.config.auth.userdetails.UserContext;
//import com.scg.jpa.entity.Member;
//import com.scg.jpa.repository.MemberRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.ApplicationContext;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.DependsOn;
//import org.springframework.context.annotation.Profile;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.access.PermissionEvaluator;
//import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
//import org.springframework.security.authentication.ReactiveAuthenticationManager;
//import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
//import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
//import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
//import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.server.SecurityWebFilterChain;
//import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
//import reactor.core.publisher.Mono;
//
//import java.io.Serializable;
//import java.util.Collections;
//
//@Profile("method")
//@Configuration
//@RequiredArgsConstructor
//// WebFlux 기반 어플리케이션에서 Spring security 사용하기 위해 선언하는 어노테이션
//@EnableWebFluxSecurity
//// 메소드 별 권한체크가 필요할 때 쓰는 annotation
//// - DefaultMethodSecurityExpressionHandler에 PermissionEvaluator를 등록하여 메소드 별 권한을 체크할 수 있다.
//@EnableReactiveMethodSecurity
//public class MethodSecurityConfig {
//
//    private final ApplicationContext applicationContext;
//
//    @Bean
//    @DependsOn({"methodSecurityExpressionHandler"})
//    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http
//                                                        , ReactiveAuthenticationManager reactiveAuthenticationManager) {
//
//        // PermissionEvaluator를 DefaultMethodSecurityExpressionHandler에 등록해주기 위해 빈을 가지고 옴.
//        DefaultMethodSecurityExpressionHandler defaultWebSecurityExpressionHandler = this.applicationContext.getBean(DefaultMethodSecurityExpressionHandler.class);
//        defaultWebSecurityExpressionHandler.setPermissionEvaluator(myPermissionEvaluator());
//
//        return http
//                .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
//                        .authenticationEntryPoint((exchange, ex) ->
//                                Mono.fromRunnable(() -> {
//                                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                                })
//                        )
//                        .accessDeniedHandler((exchange, denied) -> {
//                            return Mono.fromRunnable(() -> {
//                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
//                            });
//                        }))
//                .csrf().disable()
//                .formLogin().disable()
//                .httpBasic().disable()
//                .authenticationManager(reactiveAuthenticationManager)
//                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
//                .authorizeExchange(exchange ->
//                        exchange
//                                .pathMatchers(HttpMethod.OPTIONS).permitAll()
//                                .pathMatchers("/test").permitAll()
//                                .pathMatchers("/auth/login").permitAll()
//                                .anyExchange().authenticated())
////                .addFilterAt(new JwtTokenAuthenticationFilter(jwtTokenProvider), SecurityWebFiltersOrder.HTTP_BASIC)
//                .build();
//    }
//
//    @Bean
//    public PermissionEvaluator myPermissionEvaluator() {
//        return new PermissionEvaluator() {
//            @Override
//            public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
//                return authentication
//                        .getAuthorities()
//                        .stream()
//                        .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(targetDomainObject));
//            }
//
//            @Override
//            public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
//                return false;
//            }
//        };
//    }
//
////    @Bean
////    public ReactiveUserDetailsService userDetailsService(MemberRepository memberRepository) {
////        return username -> {
////            Member member = memberRepository.findById(username).orElse(null);
////            if (member == null) return Mono.empty();
////            UserContext userContext = new UserContext(member
////                                                    , Collections.singleton(new SimpleGrantedAuthority(member.getRole())));
////            return Mono.just(userContext);
////        };
////    }
////
////    @Bean
////    public ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService
////                                                                    , PasswordEncoder passwordEncoder) {
////        var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
////        authenticationManager.setPasswordEncoder(passwordEncoder);
////        return authenticationManager;
////    }
////
////    @Bean
////    public PasswordEncoder passwordEncoder()
////    {
////        return new BCryptPasswordEncoder();
////    }
//}
