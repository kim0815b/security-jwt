package com.kim0815.securityjwt.controller;

import com.kim0815.securityjwt.dto.JwtToken;
import com.kim0815.securityjwt.dto.SignUpDTO;
import com.kim0815.securityjwt.service.MemberServiceImpl;
import com.kim0815.securityjwt.utill.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/member")
@RequiredArgsConstructor
@Slf4j
public class MemberController {
    private final MemberServiceImpl memberService;
    @GetMapping("/login")
    public String login() {
        return "/member/login";
    }

    @PostMapping("/login")
    @ResponseBody
    public JwtToken loginProcess(@RequestBody SignUpDTO signUpDTO) {
        String username = signUpDTO.getUsername();
        String password = signUpDTO.getPassword();
        JwtToken jwtToken = memberService.signIn(username, password);
        log.info("request username = {}, password = {}", username, password);
        log.info("jwtToken accessToken = {}, refreshToken = {}", jwtToken.getAccessToken(), jwtToken.getRefreshToken());
        return jwtToken;
    }
    @PostMapping("/test")
    @ResponseBody
    public String test() {
        return SecurityUtil.getCurrentUsername();
    }

    @GetMapping("/signup")
    public String signup() {
        return "/member/signup";
    }

    @GetMapping("/success")
    @ResponseBody
    public String success() {
        return "success";
    }
    @PostMapping("/signup")
    public String signupProcess(@ModelAttribute SignUpDTO signUpDTO) {
        log.info("signup");
        log.info("member=={},==={}", signUpDTO.getUsername(), signUpDTO.getPassword());
        memberService.signUp(signUpDTO);
        return "redirect:/member/login";
    }

}
