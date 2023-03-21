package com.wish.PracticeJWT.auth;

import io.jsonwebtoken.io.Decoders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat; // 자동 임포트 안됨
import static org.hamcrest.Matchers.is; // 자동 임포트 안됨
import static org.hamcrest.Matchers.notNullValue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS) // 테스트 클래스의 인스턴스 라이프 사이클을 지정하는 데 사용하는 메서드 // 같은 클래스에서 실행되는 모든 메서드가 동일한 인스턴스 객체를 공유하게 설정했다.
public class JwtTokenizerTest {
    private static JwtTokenizer jwtTokenizer;
    private String secretKey;
    private String base64EncodedSecretKey;

    @BeforeAll // 모든 테스트 수행전에 동작하게 함
    public void init() {
        jwtTokenizer = new JwtTokenizer();
        secretKey = "kevin1234123412341234123412341234";  // encoded "a2V2aW4xMjM0MTIzNDEyMzQxMjM0MTIzNDEyMzQxMjM0"

        base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(secretKey); // 시크릿키 인코딩
    }

    @Test
    public void encodeBase64SecretKeyTest() { // 인코딩이 정상적으로 수행이 되는지 테스트
        System.out.println(base64EncodedSecretKey);

        assertThat(secretKey, is(new String(Decoders.BASE64.decode(base64EncodedSecretKey))));
    }

    @Test
    public void generateAccessTokenTest() { // Access Token을 정상적으로 생성하는지 테스트
        Map<String, Object> claims = new HashMap<>();
        claims.put("memberId", 1);
        claims.put("roles", List.of("USER"));

        String subject = "test access token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, 10); // 생성시점 +10분뒤로 설정
        Date expiration = calendar.getTime(); // 만료일시 설정

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        System.out.println(accessToken);

        assertThat(accessToken, notNullValue()); // JWT는 생성할 때마다 그 값이 바뀌기 때문에 생성된 Access Token이 null이 아닌지 여부만 테스트
    }

    @Test
    public void generateRefreshTokenTest() { // Refresh Token을 정상적으로 생성하는지 테스트
        String subject = "test refresh token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, 24); // 유효시간 24시간으로 설정
        Date expiration = calendar.getTime();

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, base64EncodedSecretKey);

        System.out.println(refreshToken);

        assertThat(refreshToken, notNullValue());
    }
}