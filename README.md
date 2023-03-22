[블로그 포스팅 주소](https://velog.io/@wish17/%EC%BD%94%EB%93%9C%EC%8A%A4%ED%85%8C%EC%9D%B4%EC%B8%A0-%EB%B0%B1%EC%97%94%EB%93%9C-%EB%B6%80%ED%8A%B8%EC%BA%A0%ED%94%84-65%EC%9D%BC%EC%B0%A8-JWT-%EC%9D%B8%EC%A6%9DAuthentication)


# JWT 인증(Authentication)

## 세션 기반 자격 증명 방식
- 서버 측에 인증된 **사용자의 정보를** 세션 형태로 세션 **저장소에 저장**하는 방식

### 세션 기반 자격 증명의 특징

- 세션은 인증된 사용자 정보를 서버 측 세션 저장소에서 관리한다.

- 생성된 사용자 세션의 고유한 ID인 세션 ID는 클라이언트의 쿠키에 저장되어 요청을 보낼 때 인증된 사용자인지를 증명하는 수단으로 사용된다.

- 클라이언트 측에서는 세션 ID만을 사용하기 때문에, 네트워크 트래픽 부담이 비교적 적다.

- 세션 정보는 서버 측에서 관리되기 때문에, 보안 측면에서 약간의 이점이 있다.

- 서버 확장성 측면에서는 세션 불일치 문제가 발생할 가능성이 있다.

- 세션 데이터 양이 증가하면 서버 부하가 증가할 수 있다.

- SSR(Server Side Rendering) 애플리케이션에 적합한 방식이다.

### 세션 기반 인증 절차

[![](https://velog.velcdn.com/images/wish17/post/c08d5b66-2009-44b8-8665-d7e22eb1d7fa/image.png)](https://velog.io/@jun7867/%EC%84%B8%EC%84%A0-%EA%B8%B0%EB%B0%98-%EC%9D%B8%EC%A6%9D%EA%B3%BC-%ED%86%A0%ED%81%B0-%EA%B8%B0%EB%B0%98-%EC%9D%B8%EC%A6%9DJWT-%EC%B0%A8%EC%9D%B4%EC%A0%90)



## 토큰 기반 인증

- 세션기반 인증방식으로 생기는 서버의 부담을 "클라이언트에게 넘겨줄순 없을까?"하는 생각에서 토큰 기반 인증이 고안되었다.
(대표적인 토큰기반 인증 = JWT)

- 클라이언트 측에 인증된 사용자의 정보를 토큰 형태로 저장하는 방식
    - 토큰: 인증된 사용자의 자격을 증명하는 동시에 접근 권한을 부여해 접근 권한이 부여된 특정 리소스에만 접근할 수 있게 하는 역할

### 토큰 기반 자격 증명의 특징
- 토큰에 포함된 인증된 사용자 정보는 서버 측에서 별도로 관리되지 않는다.

- 생성된 토큰을 헤더에 포함시켜 요청을 보낼 때, 인증된 사용자인지를 증명하는 수단으로 사용된다.

- 토큰은 인증된 사용자 정보 등을 포함하기 때문에 **세션보다 비교적 많은 네트워크 트래픽을 사용**한다.

- 토큰은 기본적으로 서버 측에서 관리되지 않기 때문에 보안 측면에서 약간의 불리함이 있다.

- 인증된 사용자 요청의 상태를 유지할 필요가 없기 때문에 **세션 불일치와 같은 문제를 일으키지 않으므로 서버의 확장성 측면에서 이점이 있다.**

- 토큰에 포함된 사용자 정보는 토큰의 특성상 암호화되어 있지 않기 때문에, 공격자가 토큰을 탈취하면 사용자 정보가 그대로 제공된다. 따라서 **민감한 정보는 토큰에 포함시키지 않아야 한다.**

- 토큰은 기본적으로 **만료될 때까지 무효화될 수 없다.**

- CSR(Client Side Rendering) 기반 애플리케이션에 적합한 방식이다.

***

## JWT(JSON Web Token)

> JWT
- 가장 범용적으로 사용되는 토큰 인증 방식
-  JSON 포맷의 토큰 정보를 인코딩 후, 인코딩된 토큰 정보를 Secret Key로 서명(Sign)한 메시지를 Web Token으로써 인증 과정에 사용

### JWT의 종류

1. 액세스 토큰(Access Token)
- 보호된 정보들(사용자의 이메일, 연락처, 사진 등)에 접근할 수 있는 **권한 부여에 사용**
- 비교적 짧은 유효 기간을 주어 탈취되더라도 오랫동안 사용할 수 없도록 한다.

2. 리프레시 토큰(Refresh Token)

- Access Token의 유효기간이 만료된다면 Refresh Token을 사용하여 새로운 Access Token을 발급받는다. 
    - 이때, 사용자는 다시 로그인 인증을 할 필요가 없다.

- Refresh Token을 탈취당한다면 Access Token을 계속 발급할 수 있기 때문에 보안상의 문제가 있다.
    - 사용자의 편의보다 정보를 지키는 것이 더 중요한 웹 애플리케이션은 Refresh Token을 사용하지 않는 것이 좋다.

### JWT 구조

[![](https://velog.velcdn.com/images/wish17/post/38e78db3-7d46-491b-b2b4-351c1a5e6071/image.png)](https://velopert.com/2389)


####  Header
- 어떤 종류의 토큰인지(지금의 경우엔 JWT), 어떤 알고리즘으로 Sign할지 정의
```
{
  "alg": "HS256",
  "typ": "JWT"
}
// 이 JSON 객체를 base64 방식으로 인코딩하면 JWT의 Header가 된다.
```

#### Payload

- 서버에서 활용할 수 있는 사용자의 정보와 권한을 담는 부분
    - 민감한 정보(비번 등)는 담지 않는 것이 좋다.


```
{
  "sub": "홍길동은 잘생겼다",
  "name": "홍길동",
  "iat": 151623391
}
// 이 JSON 객체를 base64 방식으로 인코딩하면 JWT의 Payload가 된다.
```

#### Signature

- 토큰의 위변조 유무를 검증하는 데 사용

- base64로 Header와 Payload 부분을 인코딩한 뒤 원하는 비밀 키(Secret Key)와 Header에서 지정한 알고리즘을 사용하여 Header와 Payload에 대해서 단방향 암호화를 수행

```
HMACSHA256(base64UrlEncode(header) + '.' + base64UrlEncode(payload), secret);
```

### 토큰 기반 인증 절차

[![](https://velog.velcdn.com/images/wish17/post/80f80964-9ee8-4271-a814-87d5097507fd/image.png)](https://velog.io/@jun7867/%EC%84%B8%EC%84%A0-%EA%B8%B0%EB%B0%98-%EC%9D%B8%EC%A6%9D%EA%B3%BC-%ED%86%A0%ED%81%B0-%EA%B8%B0%EB%B0%98-%EC%9D%B8%EC%A6%9DJWT-%EC%B0%A8%EC%9D%B4%EC%A0%90)

### 핵심 포인트

- JWT는 일반적으로 다음과 액세스 토큰(Access Token)과 리프레시 토큰(Refresh Token)을 사용자의 자격 증명에 이용한다.

- Access Token에는 비교적 짧은 유효 기간 을 주어 탈취되더라도 오랫동안 사용할 수 없도록 하는 것이 권장된다.

- JWT는 Header.Payload.Signature의 구조로 이루어진다.

- Base64로 인코딩되는 Payload는 손쉽게 디코딩이 가능하므로 민감한 정보는 포함하지 않아야 한다.

***

## JWT의 장점과 단점

### JWT를 통한 인증의 장점

- 상태를 유지하지 않고(Stateless), 확장에 용이한(Scalable) 애플리케이션을 구현하기 용이하다.
    - 서버는 클라이언트에 대한 정보를 저장할 필요 없다.
    	- 서버 부담 down
       - 토큰 검증만 함
    - 클라이언트는 request를 전송할 때마다 토큰을 헤더에 포함시키기만 하면 된다.
    	- 세션방식은 모든 서버가 사용자의 세션 정보를 공유해야 한다.
       - 여러 서버를 이용하는 서비스일 때 JWT는 효과적이다.

- 클라이언트가 request를 전송할 때마다 자격 증명 정보를 전송할 필요가 없다.
    - JWT의 경우 토큰이 만료되기 전까지는 한 번의 인증만 수행하면 된다.

- 인증 시스템을 다른 플랫폼으로 분리하기 용이하다.
    - Github나 Google과 같은 다른 플랫폼의 자격 증명을 사용하여 사용자 자격 증명을 직접 관리하지 않아도 된다.
    - 토큰 생성을 위한 서버를 생성하거나, 다른 회사에게 토큰 관련 작업을 위탁하는 등 다양한 방식으로 사용할 수 있다.
    

- 사용자의 인가(권한 부여) 정보를 토큰의 Payload(내용물)에 쉽게 포함시킬 수 있다.

### JWT를 통한 인증의 단점

<ul><li><p>Payload를 디코딩하기 쉬워 보안이 취약하다.</p><ul><li>Payload는 base64로 인코딩되기 때문에 토큰을 탈취하여 디코딩하면 저장된 데이터를 확인할 수 있다.</li><li>따라서 Payload에 민감한 정보를 담아서는 안된다.</li></ul></li><li><p>토큰 길이가 길어지면 네트워크 부하가 증가될 가능성이 있다.</p><ul><li>토큰에 저장하는 정보의 양이 많아질수록 토큰의 길이는 길어진다.</li><li>따라서 request를 전송할 때마다 길이가 긴 토큰을 함께 전송하면 네트워크 부하를 일으킬 수 있다.</li></ul></li><li><p>토큰이 자동으로 삭제되지 않는다.</p><ul><li>한 번 생성된 토큰은 자동으로 삭제되지 않기 때문에 반드시 토큰 만료 시간을 설정해야 한다.</li><li>만료 시간을 너무 길게 설정하면 토큰이 탈취된 경우 탈취자가 해당 토큰을 계속 이용할 수 있으므로 보안에 취약해진다.</li></ul></li></ul>

***

## JWT 생성 및 검증 테스트

[풀코드 Github](https://github.com/wish9/Practice-JWT/commits/master)

```java
public void verifySignature(String jws, String base64EncodedSecretKey) {
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key)     // 서명에 사용된 Secret Key를 설정
                .build()
                .parseClaimsJws(jws);   //  JWT를 파싱해서 Claims를 얻어내기 // (jws)는 Signature가 포함된 JWT라는 의미
    }
// parseClaimsJws(jws)메서드 자체가 검증하는 로직이다.
// jws에서 Claims을 얻어내 base64EncodedSecretKey와 같은지 비교
```


> Claims
- JWT의 내용(payload)에 포함된 JSON 형태의 객체


```java
@DisplayName("throw ExpiredJwtException when jws verify")
@Test
public void verifyExpirationTest() throws InterruptedException { // 토큰 만료되고 ExpiredJwtException이 발생하는지 테스트
    String accessToken = getAccessToken(Calendar.SECOND, 1);
    assertDoesNotThrow(() -> jwtTokenizer.verifySignature(accessToken, base64EncodedSecretKey)); // 여기서는 통과

    TimeUnit.MILLISECONDS.sleep(1500);

    assertThrows(ExpiredJwtException.class, () -> jwtTokenizer.verifySignature(accessToken, base64EncodedSecretKey)); // 여기서는 1초 지났으니 토큰만료되고 실패
}
```

>throws InterruptedException이 붙은 이유
- InterruptedException은 sleep() 메서드에서 발생할 수 있는 예외다. 이 메서드에서는 스레드를 1.5초 동안 중지한 후 ExpiredJwtException이 발생하는지 테스트하기 위해 사용되었다. 이러한 경우, 다른 스레드가 현재 실행중인 스레드를 깨울 수도 있으므로 InterruptedException을 처리해줘야 한다.

### 핵심 포인트

- Plain Text 자체를 Secret Key로 사용하는 것은 권장되지 않는다.

- jjwt 최신 버전(0.11.5)에서는 서명 과정에서 HMAC 알고리즘을 직접 지정하지 않고, 내부적으로 적절한 HMAC 알고리즘을 지정해 준다.
