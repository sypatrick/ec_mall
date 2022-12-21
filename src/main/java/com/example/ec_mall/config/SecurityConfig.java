package com.example.ec_mall.config;

import com.example.ec_mall.mapper.MemberMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * SpringSecurity
 * 자바 서버 개발을 위해 필요로 한 인증, 권한 부여 및 기타 보안 기능을 제공하는 프레임워크(클래스와 인터페이스 모임)
 */
@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig{
    private final MemberMapper memberMapper;

    @Bean
    public UserDetailsService userDetailsService(){
        return new UserDetailsServiceImpl(memberMapper);
    }

    /**
     * org.springframework.security.crypto.. 에 보면 다양한 암호화 방식을 적용할 수 있다.
     * 해당 Encoder들은 PasswordEncoder 인터페이스의 구현체들이며
     * encode(), boolean 타입의 matches() 등의 메소드를 활용할 수 있다.
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    // 동시 세션 제어를 위한 이벤트퍼블리셔
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher(){
        return new HttpSessionEventPublisher();
    }

    /**
     *  5.7.1부터 기존 configure(HttpSecurity http) 메소드를 오버라이드 하여 설정해주던 방식에서
     *  SecurityFilterChain 빈을 등록하여 사용하는 방법을 권장하고 있다.
     *  cf (https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .csrf().disable() //csrf 토큰 비활성화(테스트 시), security 는 해당 토큰 있어야 접근 가능
                .formLogin() // 로그인 폼 아래와 같이 설정
                .loginPage("/member/signIn") //로그인 페이지, 인증을 필요로 하는 endpoint에 접근했을 때 해당 url로 이동
                .loginProcessingUrl("/member/doSignIn") //post 요청이 오면 로그인 처리를 수행, 스프링 시큐리티가 해당 주소로 요청오는 로그인 로직 가져감 (loadUserByUsername)
                .usernameParameter("email")
                .passwordParameter("password") //password 같은경우 매개변수 초기값이 password 이다.(매개변수명이 password라면 생략가능)
                .defaultSuccessUrl("/") // 인증 성공시 redirect page
                .failureUrl("/member/login?fail=true"); // 실패 시
        /**
         * sessionCreationPolicy
         * Always 세션 없다면 항상 생성
         * ifRequired 필요한 경우에만 세션 생성 (기본 값)
         * never 프레임 워크에서 세션 생성하지 않지만 이미 존재하는 경우 세션 사용
         * stateless 세션 사용 안함
         *
         * cf) https://www.baeldung.com/spring-security-session
         */
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/member/signIn"); //유효하지 않은 세션일 경우 리다이렉트
        http
                .sessionManagement()
                .maximumSessions(1) // 세션 최대 허용 수
                .maxSessionsPreventsLogin(false); // false : 중복 로그인시 이전 로그인 로그아웃 처리
        http
                .authorizeRequests() //인가 요청 관련
                .antMatchers("/","/member/signUp","/member/signIn","/member/doSignIn", "/member/profile")// 해당 경로들은
                .permitAll() // 접근을 허용
                .anyRequest().authenticated(); // 다른 모든 요청은 인증이 되어야 들어갈 수 있음.


        return http.build();
    }
}
