package com.example.ec_mall.service;

import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.dto.jwt.TokenDto;
import com.example.ec_mall.dto.request.MemberRequestDTO.RequestDTO;
import com.example.ec_mall.dto.request.MemberRequestDTO.LoginDTO;
import com.example.ec_mall.exception.APIException;
import com.example.ec_mall.exception.ErrorCode;
import com.example.ec_mall.exception.JwtCustomException;
import com.example.ec_mall.jwt.JwtTokenProvider;
import com.example.ec_mall.mapper.MemberMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@Log4j2
@RequiredArgsConstructor
public class AuthService {
    private final MemberMapper memberMapper;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    /**
     * 유저의 정보로 회원가입
     * @param memberRequestDTO 가입할 유저의 정보 Dto
     * @return 가입된 유저 정보
     */
    @Transactional
    public int signUpMember(RequestDTO memberRequestDTO) {

        MemberDao member = MemberDao.builder()
                .email(memberRequestDTO.getEmail())
                .nickName(memberRequestDTO.getNickName())
                .password(bCryptPasswordEncoder.encode(memberRequestDTO.getPassword()))
                .createdBy(memberRequestDTO.getEmail())
                .build();
        /**
         * Log 레벨
         * trace < debug < info < warn < error
         * 오른쪽으로 갈수록 심각한 오류
         *
         * 하위 레벨의 로그는 상위 레벨의 로그를 포함
         * ex) debug로 설정시 info, warn, error 로그를 포함하여 출력
         */
        //email 중복체크
        boolean dupCheckEmail = isDuplicatedEmail(member.getEmail());
        if(dupCheckEmail){
            log.error("DuplicatedEmail, {}", member.getEmail());
            throw new APIException(ErrorCode.ALREADY_SAVED_EMAIL);
        }
//
//        if(memberMapper.signUpMember(member) != 1){
//            log.error("registration ERROR! {}", member);
//            throw new RuntimeException("회원가입 메소드 확인\n" + member);
//        }
        return memberMapper.signUpMember(member);
    }

    private boolean isDuplicatedEmail(String email){
        return memberMapper.emailCheck(email) == 1;
    }
    /**
     * 유저 정보로 로그인
     * @param signInReq 유저의 이메일과 비밀번호
     * @return json web token
     */
    public ResponseEntity<TokenDto> signIn(LoginDTO signInReq) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signInReq.getEmail(),
                            signInReq.getPassword()
                    )
            );
            TokenDto tokenDto = new TokenDto(jwtTokenProvider.generateToken(authentication));
            System.out.println(signInReq.getEmail());

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add("Authorization", "Bearer " + tokenDto.getAccess_token());

            return new ResponseEntity<>(tokenDto, httpHeaders, HttpStatus.OK);
    }
}