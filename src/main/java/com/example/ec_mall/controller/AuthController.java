package com.example.ec_mall.controller;

import com.example.ec_mall.dto.jwt.TokenDto;
import com.example.ec_mall.service.AuthService;
import com.example.ec_mall.dto.request.MemberRequestDTO.RequestDTO;
import com.example.ec_mall.dto.request.MemberRequestDTO.LoginDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Objects;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @GetMapping("/signUp")
    public String signUp() {
        return "member/signUp";
    }

    @PostMapping("/signUp")
    public String signUp(@Valid @RequestBody RequestDTO signUpReq) {
        int isSignUp = authService.signUpMember(signUpReq);

        if(isSignUp == 1) { // 회원가입 성공시 1 반환
            return "redirect:/member/signIn"; // 1이 반환되면 로그인 페이지 리다이렉트
        }
        return "redirect:/member/signUp"; // 1이 아닐경우 회원가입 페이지 리다이렉트
    }

    @GetMapping("/signIn")
    public String signIn(@RequestParam(value = "fail", required = false) String flag, Model model) {
        model.addAttribute("failed", flag != null);

        return "member/signIn";
    }

    @PostMapping("/signIn")
    public String signIn(@Valid @RequestBody LoginDTO signInReq, HttpServletResponse res) {
        ResponseEntity<TokenDto> tokenDtoResponseEntity = authService.signIn(signInReq);
        Cookie cookie = new Cookie(
                "access_token",
                Objects.requireNonNull(tokenDtoResponseEntity.getBody()).getAccess_token()
        );

        cookie.setPath("/");
        cookie.setMaxAge(Integer.MAX_VALUE);

        res.addCookie(cookie);
        return "redirect:/member/profile";
    }
}
