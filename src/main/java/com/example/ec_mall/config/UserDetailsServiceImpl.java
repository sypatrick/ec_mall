package com.example.ec_mall.config;

import java.util.HashSet;
import java.util.Set;

import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.mapper.MemberMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final MemberMapper memberMapper;

    @Override
    public UserDetails loadUserByUsername(String email) {
        MemberDao memberDao = memberMapper.findByEmail(email);
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        return new org
                .springframework
                .security
                .core
                .userdetails
                .User(memberDao.getEmail(), memberDao.getPassword(), grantedAuthorities);
    }
}
