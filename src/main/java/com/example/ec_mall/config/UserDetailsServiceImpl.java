package com.example.ec_mall.config;

import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.mapper.MemberMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.HashSet;
import java.util.Set;

@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final MemberMapper memberMapper;

    @Override
    public UserDetails loadUserByUsername(String email){

        MemberDao member = memberMapper.findByEmail(email);
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        return new org
                .springframework
                .security
                .core
                .userdetails
                .User(member.getEmail(), member.getPassword(), grantedAuthorities);
    }
}
