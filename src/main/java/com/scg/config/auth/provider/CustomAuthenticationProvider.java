//package com.scg.config.auth.provider;
//
//import com.scg.config.auth.token.CustomAuthenticationToken;
//import com.scg.config.auth.userdetails.UserContext;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//@Slf4j
//public class CustomAuthenticationProvider implements AuthenticationProvider {
//
//    @Autowired
//    UserDetailsService userDetailsService;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        String userId = authentication.getName();
//        String password = (String) authentication.getPrincipal();
//
//        UserContext userContext = (UserContext) userDetailsService.loadUserByUsername(userId);
//        if(!passwordEncoder.matches(password, userContext.getPassword())) {
//            throw new BadCredentialsException("Invalid Password");
//        }
//
//        return new CustomAuthenticationToken(userContext, null, userContext.getAuthorities());
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return CustomAuthenticationToken.class.isAssignableFrom(authentication);
//    }
//}
