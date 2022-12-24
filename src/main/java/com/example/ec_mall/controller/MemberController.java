package com.example.ec_mall.controller;

import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
   @RestController
    -> @Controller + @ResponseBody

   @Controller의 역할은 Model객체를 만들어 데이터를 담고 View를 찾는다.
   @RestController는 단순히 객체만을 반환하고 객체 데이터는 JSON 또는 XML 형식으로 HTTP응답에 담아서 전송.
 */
@Controller
@RequiredArgsConstructor
@RequestMapping(value = "/member")
public class MemberController {
    private final MemberService memberService;
    @GetMapping("/profile")
    public String profile(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails != null) {
            MemberDao memberDao = memberService.profile(userDetails.getUsername());

            model.addAttribute("memberDao", memberDao);
        }
        else System.out.println("tlqkf");
        return "member/profile";
    }
}