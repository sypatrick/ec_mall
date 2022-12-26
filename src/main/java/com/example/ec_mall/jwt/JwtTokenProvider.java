package com.example.ec_mall.jwt;

import com.example.ec_mall.dto.jwt.TokenDto;
import com.example.ec_mall.exception.JwtCustomException;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    @Value("${jwt.token.secret-key}")
    private String secret_key;

    @Value("${jwt.token.expire-length}")
    private long expire_time;

    private final UserDetailsService userDetailsService;

    /**
     * 적절한 설정을 통해 토큰을 생성하여 반환
     * @param authentication
     * @return
     */

    public TokenDto generateToken(Authentication authentication) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        // Access Token 생성
        Date accessTokenExpiresIn = new Date(now + expire_time);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", "ROLE_USER")
                .setExpiration(accessTokenExpiresIn)
                .signWith(SignatureAlgorithm.HS256, secret_key)
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + expire_time))
                .signWith(SignatureAlgorithm.HS256, secret_key)
                .compact();

        return TokenDto.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
//    public String generateToken(Authentication authentication) {
//        Claims claims = Jwts.claims().setSubject(authentication.getName());
//
//        Date now = new Date();
//        Date expiresIn = new Date(now.getTime() + expire_time);
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setIssuedAt(now)
//                .setExpiration(expiresIn)
//                .signWith(SignatureAlgorithm.HS256, secret_key)
//                .compact();
//    }

    /**
     * 토큰으로부터 클레임을 만들고, 이를 통해 User 객체를 생성하여 Authentication 객체를 반환
     * @param accessToken
     * @return
     */

    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }
//    public Authentication getAuthentication(String token) {
//        String username = Jwts.parser().setSigningKey(secret_key).parseClaimsJws(token).getBody().getSubject();
//        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
//    }
    /**
     * http 헤더로부터 bearer 토큰을 가져옴.
     * @param req
     * @return
     */
    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * 토큰을 검증
     * @param token
     * @return
     */


    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secret_key).parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            // MalformedJwtException | ExpiredJwtException | IllegalArgumentException
            throw new JwtCustomException("Error on Token", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parser().setSigningKey(secret_key).parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}