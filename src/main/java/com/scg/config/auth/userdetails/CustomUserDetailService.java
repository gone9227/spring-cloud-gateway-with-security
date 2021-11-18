//package com.scg.config.auth.userdetails;
//
//import com.scg.jpa.entity.Member;
//import com.scg.jpa.repository.MemberRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.*;
//import org.springframework.stereotype.Service;
//import reactor.core.publisher.Mono;
//
//import java.util.Collections;
//
//@Service("userDetailsService")
//@RequiredArgsConstructor
//public class CustomUserDetailService implements ReactiveUserDetailsService {
//
//    private final MemberRepository memberRepository;
//
////    @Override
////    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
////        Member member = memberRepository
////                            .findById(username)
////                            .orElseThrow(()
////                                    -> new UsernameNotFoundException(username + " Not Found"));
////
////        return new UserContext(
////                member
////                , Collections.singleton(new SimpleGrantedAuthority(member.getRole()))
////        );
////    }
//
//    @Override
//    public Mono<UserDetails> findByUsername(String username) {
//        return null;
//    }
//}
