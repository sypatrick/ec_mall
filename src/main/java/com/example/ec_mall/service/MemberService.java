package com.example.ec_mall.service;


import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.mapper.MemberMapper;
import lombok.RequiredArgsConstructor;

import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Log4j2
public class MemberService {
    private final MemberMapper memberMapper;
    public MemberDao profile(String email){
        return memberMapper.findByEmail(email);
    }
}
