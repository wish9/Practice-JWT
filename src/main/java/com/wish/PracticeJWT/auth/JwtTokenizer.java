package com.wish.PracticeJWT.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public class JwtTokenizer {
    public String encodeBase64SecretKey(String secretKey) {
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8)); // Plain Text 형태인 Secret Key의 byte[]를 Base64 형식의 문자열로 인코딩
    }

    // 인증된 사용자에게 JWT를 최초로 발급해주기 위한 JWT 생성 메서드
    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims)          // JWT에 포함 시킬 Custom Claims를 추가 // Claims = 주로 인증된 사용자와 관련된 정보
                .setSubject(subject)        // JWT에 대한 제목을 추가
                .setIssuedAt(Calendar.getInstance().getTime())   // JWT 발행 일자를 설정 // 파라미터 타입 = java.util.Date
                .setExpiration(expiration)  // JWT의 만료일시를 지정 // 파라미터 타입 = java.util.Date
                .signWith(key)              // 서명에 사용할 Key(java.security.Key) 객체를 설정
                .compact();                 // 최종적으로 JWT를 생성하고 직렬화
    }

    //  Access Token이 만료되었을 경우, Access Token을 새로 생성할 수 있게 해주는 Refresh Token을 생성하는 메서드
    public String generateRefreshToken(String subject, Date expiration, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }


    // JWT의 서명에 사용할 Secret Key를 생성하는 메서드
    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);  // Base64 형식으로 인코딩된 Secret Key를 디코딩한 후, byte array를 반환
        Key key = Keys.hmacShaKeyFor(keyBytes);    // key byte array를 기반으로 적절한 HMAC 알고리즘을 적용한 Key(java.security.Key) 객체를 생성

        return key;
    }

    public void verifySignature(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key)     // 서명에 사용된 Secret Key를 설정
                .build()
                .parseClaimsJws(jws);   //  JWT를 파싱해서 Claims를 얻어내기 // jws는 Signature가 포함된 JWT라는 의미
        // parseClaimsJws(jws)메서드 자체가 검증하는 로직이다.
        // jws에서 Claims을 얻어내 base64EncodedSecretKey와 같은지 비교
    }
}
