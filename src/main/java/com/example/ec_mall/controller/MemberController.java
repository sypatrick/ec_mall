package com.example.ec_mall.controller;

import com.example.ec_mall.dao.MemberDao;
import com.example.ec_mall.dto.request.MemberRequestDTO;
import com.example.ec_mall.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
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

    @GetMapping("/signUp")
    public String signUp() {
        return "member/signUp";
    }
    @PostMapping("/signUp")
    public String signUpMember(@Validated MemberRequestDTO.RequestDTO memberRequestDTO) {
        memberService.signUpMember(memberRequestDTO);
        return "redirect:/member/signIn";
    }

    /**
     * 로그인 (Email, Password)
     * @param memberLoginDTO : Email, Password
     * @return
     */
//    @PostMapping("/login")
//    public ResponseEntity<MemberDao> login(@RequestBody @Valid MemberRequestDTO.LoginDTO memberLoginDTO, HttpSession session){
//        memberService.login(memberLoginDTO.getEmail(), memberLoginDTO.getPassword());
//        session.setAttribute("account", memberLoginDTO.getEmail());
//        return ResponseEntity.status(HttpStatus.OK).build();
//    }

    /**
     * Spring security 가 로그인 가로채서 로그인 처리하기 때문에 postmapping 이 아닌 getmapping 처리
     */
    @GetMapping("/signIn")
    public String signIn(@RequestParam(value = "fail", required = false) String flag, Model model) {
        model.addAttribute("failed", flag != null);

        return "member/signIn";
    }

    @GetMapping("/profile")
    public String profile(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails != null) {
            MemberDao memberDao = memberService.profile(userDetails.getUsername());

            model.addAttribute("memberDao", memberDao);
        }

        return "member/profile";
    }
}