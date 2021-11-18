package com.scg.config.auth.userdetails;

import com.scg.jpa.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class UserContext extends User {

    private final Member member;

    public UserContext(Member member, Collection<? extends GrantedAuthority> authorities) {
        super(member.getUserId(), member.getPassword(), authorities);
        this.member = member;
    }

    public Member getMember(){
        return member;
    }
}
