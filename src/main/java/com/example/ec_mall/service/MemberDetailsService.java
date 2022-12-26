package com.example.ec_mall.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.mapper.MemberMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberDetailsService implements UserDetailsService {
    private final MemberMapper memberMapper;

    @Override
    public UserDetails loadUserByUsername(String email) {
        System.out.println("email in loadUserByUsername = " + email);
        MemberDao memberDao = memberMapper.findByEmail(email);
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        System.out.println("roles in loadUserByUsername = " + memberDao.getAuthorities());
        //return new User(memberDao.getEmail(), memberDao.getPassword(), grantedAuthorities);
        return User.builder()
                .username(memberDao.getUsername())
                .password(memberDao.getPassword())
                .roles(memberDao.getRoles().toArray(new String[0]))
                .build();
    }
}