package com.scg.config.auth.userdetails;

import com.scg.jpa.entity.Member;
import com.scg.jpa.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

import java.util.Collections;

@RequiredArgsConstructor
public class CustomUserDetailService implements ReactiveUserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        Member member = memberRepository.findById(username).orElse(null);
        if (member == null) return Mono.empty();
        UserContext userContext = new UserContext(member
                                                , Collections.singleton(new SimpleGrantedAuthority(member.getRole())));
        return Mono.just(userContext);
    }
}
