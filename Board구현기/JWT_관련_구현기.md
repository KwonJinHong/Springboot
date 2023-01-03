# Board API Project - 로그인과 JWT을 통한 인증 (2)

저번 글을 통해 로그인에 대한 내용을 다루었다. 이제는 JWT에 대한 내용을 다뤄볼려고 한다. JWT에 대해 이야기 하기 전에, 간단하게 왜 JWT가 필요한가에 대한 이야기를 해보려한다.
 
 기본적으로 HTTP는 STATELESS한 특성을 가지기 때문에 각 통신(Request)의 상태는 서로 독립적이다. 즉 각 통신의 상태가 저장되지 않는다. 그렇다면 새 페이지를 요청할 때마다 로그인을 해야하는가? 라는 의문이 들 것이다. 하지만 우리는 웹 서비스를 이용할 때 그렇지 않다는 것을 알고있다.
 
 위에 말한 문제를 해결하기 위한 대표적인 방식이 세션(Session)과 토큰(Token)이다. 
 
 유저가 로그인을 시도할 때 서버상에서 일치하는 유저를 찾았다면, 인증(Authentication)이 되었단 확인의 표시로 세션이나 토큰을 발급/전달해준다.
 
 그럼 웹 브라우저측에서 해당 세션이나 토큰 정보를 받아 갖고 있다가 새로운 요청(Request)가 들어올 때마다 인가(Authorization)을 위해 해당 세션/토큰을 함께 보내게 된다.
 
 하지만 두 방식은 서로 장단점이 있고, 차이점이 존재한다. 이에 대한 이야기는 다른 글에서 다뤄볼것이다.
 
 이번 글에서는 JWT가 무엇이고, 어떻게 프로젝트에 적용하였는지 이야기 하겠다.
 
 ## JWT(JSON WEB TOKEN)
 
 ### JWT가 뭐지?
 
 JWT(JSON WEB TOKEN)은 당사자들간의 정보를 JSON 객체로 안전하게 전송하기 위한 개방형 표준(RFC 7519)라고 한다. 
 JWT는 RSA나 HMAC 알고리즘으로 공개/개인 키쌍 혹은 시크릿(HMAC 알고리즘)을 사용하여 서명할 수 있다. 서명된 토큰은 그 안에 포함된 정보의 무결성을 검증할 수 있고, 암호화된 토큰은 그러한 정보들을 다른 사람으로부터 숨길 수 있다.
 
 ---
 
 ### JWT는 언제 사용하지?
 - 권한 부여(Authorization) : JWT를 사용하기 위한 가장 일반적인 사용처이며, 사용자가 로그인하면 이후의 각 요청에는 JWT가 포함되어 사용자가 해당 토큰으로 허용된 경로, 서비스 및 리소스에 액세스할 수 있다.
 
 - 정보 교환 : JWT는 당사자들간의 정보를 안전하게 전송할 수 있게 해준다. JWT는 RSA나 HMAC 알고리즘으로 서명할 수 있기 때문에 보낸 사람이 누구인지 확인할 수 있다. 또한 헤더나 페이로드를 사용하여 서명을 만드므로 내용이 조작되지 않았는지도 확인할 수 있다. 

---

### JWT의 구조

JWT는 Header, Payload, Signatuer 이 세 부분으로 나뉜 구조를 갖고 있고, '.'으로 구분된다.

#### Header
토큰의 타입과 헤싱 알고리즘(암호화 방식)을 지정한다.

```java
{
  "alg": "HS256",
  "typ": "JWT"
}
```

---

#### Payload
```java
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```
토큰에 담을 정보이다. 이곳에 담기는 정보의 한조각을 `클레임`이라고 한다. 클레임의 종류에는 3가지가 있는데 내용은 아래와 같다.
- 등록된 클레임 : 토큰에 대한 정보들을 담기위해 이미 정해져 있는 클레임
- 공개 클레임 : 사용자 정의 클레임으로 공개용 정보 전달을 위해 사용
- 비공개 클레임 : 당사자간 정보를 공유하기 위해 만들어진 사용자 공개 클레임

---

#### Signature
```java
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-256-bit-secret

)
```
토큰을 인코딩하거나 유효성 검증을 할 때 사용하는 고유한 암호화 코드이다.

서명(Signature)은 헤더와 페이로드 값을 각 각 Base64로 인코딩하고, 인코딩한 값을 비밀키(secret)를 사용하여 헤더에서 정한 알고리즘으로 해싱을 한 후에 다시 Base64로 인코딩하여 생성한다. (주의점에서도 언급을 하겠지만, 비밀키(secret)은 되도록이면 복잡하게 만들고 잘 관리해야한다.)

서버에서 클라이언트로부터 JWT를 받았을 때, JWT의 헤더와 페이로드들을 서버에서 똑같이 같은 알고리즘(약속된 암호화 방식)으로 암호화하여 클라이언트가 보낸 JWT의 서명(Signature)와 같다면 해당 당사자가 요청된 것으로 알고 검증하게 된다.

---

### JWT를 쓸 때 주의점

일단 JWT의 장점은 Stateless하다는 것이다. 즉 사용자가 많이 있어도 서버에 걸리는 부하가 적다는 점이 큰 장점이다.

하지만 JWT를 사용할 때 주의할 점들이 있어 이 내용을 정리하고자 한다.
1. Header 부분 : 헤더의 "alg" 부분을 NONE으로 하여 공격을 하는 경우가 있다고 한다. 그러므로 꼭 헤더의 alg 부분을 설정해주자!
2. JWT는 변환이 쉽다. 그렇기 때문에 최소한의 정보만을 넣고 중요한 정보들은 넣지말자!
3. 시크릿키 문제 : 대충적으면 뚫릴 위험도 크기 때문에 신경써서 만들자. 좀 더 신경을 쓰자면 검증용키와 생성용키 2개 사용하는 방법도 있다고 한다.
4. JWT 탈취 문제 : 구조상 JWT의 회수나 정지가 힘들다. 이러한 문제를 해결하기 위한 방법은 JWT 블랙리스트 운용, Refresh Token Rotation 등등이 있다.

---

### JWT를 왜 씀?

 Access Token만 사용하는 경우 위에서 언급한 장점중 Stateless하게 인증 등 정보 처리가 가능하다.
 
 하지만 탈취 문제를 해결하기 위해 Refresh Token을 도입하는 순간, DB에 이 정보를 저장하게 된다면 세션과 별 다를점이 없어보이게 된다. 그래도 세션 방식에 비해서 Refresh Token이 만료된 경우에만 DB에 접근하기 때문에 I/O가 줄게되어 성능이 향상된다고 한다.
 
 ---
 
 ## 프로젝트에 JWT 적용
 
 JWT 오픈소스 라이브러리 사용 : [auth0/java-jwt](https://github.com/auth0/java-jwt)
 
 일단 대략적으로 설명하자면, "/login"을 제외한 모든 요청에 대해서 작동하게 했다. 
 
 또 Access Token과 Refresh Token을 포함하여 요청이 전송되는 경우 4가지가 존재한다.
 - Case1: Access Token과 Refresh Token이 모두 없거나 유효하지 않은 경우는 인증 실패로 처리

- Case2: Access Token은 유효하고 Refresh Token은 없거나 유효하지 않은 경우는 인증은 되나 Refresh Token을 재발급 해주지는 않음

- Case3 : Access Token은 없거나 유효하지않고, Refresh Token은 유효할 경우에는 Access Token을 재발급 해준다.

- Case4 : Access Token과 Refresh Token 둘 다 유효한 경우는 인증을 진행하지 않고 Access Token을 재발급해준다.

Case2번에서 Refresh Token을 재발급 해주지 않은 이유는 Access Token은 유효 기간이 짧기 때문에 유출이 되더라도 피해가 어느정도 최소화되는 반면에 Refresh Token은 유효 기간이 길어서 유출되었을 때 피해가 커진다고 생각했다. 탈취당했을 경우를 생각해서 Refresh Token은 재발급 해주지 않았다.

그럼 Case3번에서 Access Token을 재발급 해주는 이유는 Access Token이 유효기간이 짧아서 먼저 만료되고 Refresh Token은 유효한 경우가 있을 거라 생각했기 때문이다.

---

### JwtService
```java
@Transactional
@Service
@RequiredArgsConstructor
@Setter(value = AccessLevel.PRIVATE)
public class JwtService {

    @Value("${jwt.secret}")
    private String secret; // 서버가 갖고 있는 시크릿

    @Value("${jwt.access.expiration}")
    private long accessTokenValidityInSeconds; // Access Token 유효 시간

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenValidityInSeconds; // Refresh Token 유효 시간

    @Value("${jwt.access.header}")
    private String accessHeader; // Access Token 헤더

    @Value("${jwt.refresh.header}")
    private String refreshHeader; // Refresh Token 헤더

    //자주 쓰이는 문자열 변수로 선언언
    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String USERNAME_CLAIM = "username";

    private static final String BEARER = "Bearer ";

    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    /**
     * Access Token 생성 메서드
     * username을 클레임으로 사용
     * */
    public String createAccessToken(String username) {
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenValidityInSeconds * 1000))
                .withClaim(USERNAME_CLAIM, username)
                .sign(Algorithm.HMAC512(secret));
    }

    /**
     * Refresh Token 생성 메서드
     * Access Token 재발급하는 용도로 사용할 것이기 때문에 다른 정보를 넣지 않았다.
     * DB의 users 테이블에 저장하여 관리
     * */
    public String createRefreshToken() {
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenValidityInSeconds * 1000))
                .sign(Algorithm.HMAC512(secret));
    }

    /**
     * Refresh Token 업데이트 메서드
     * */
    public void updateRefreshToken(String username, String refreshToken) {
        userRepository.findByUsername(username)
                .ifPresentOrElse(
                        user -> user.updateRefreshToken(refreshToken),
                        () -> new Exception("유저가 없습니다")
                );
    }

    /**
     * Refresh Token 제거 메서드
     * */
    public void removeRefreshToken(String username) {
        userRepository.findByUsername(username)
                .ifPresentOrElse(
                        user -> user.removeRefreshToken(),
                        () -> new Exception("유저가 없습니다")
                );
    }

    /**
     * Access Token과 Refresh Token을 response 헤더에 넣어준다.
     * Access Token과 Refresh Token을 둘다 필요할 때 사용
     * */
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken){
        response.setStatus(HttpServletResponse.SC_OK);

        setAccessTokenHeader(response, accessToken);
        setRefreshTokenHeader(response, refreshToken);

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put(ACCESS_TOKEN_SUBJECT, accessToken);
        tokenMap.put(REFRESH_TOKEN_SUBJECT, refreshToken);

    }

    /**
     * Access Token을 response 헤더에 넣는다.
     * Access Token 만 필요할 때 사용
     * */
    public void sendAccessToken(HttpServletResponse response, String accessToken){
        response.setStatus(HttpServletResponse.SC_OK);

        setAccessTokenHeader(response, accessToken);

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put(ACCESS_TOKEN_SUBJECT, accessToken);
    }

    /**
     * Access Token을 request 헤더에서 추출
     * */
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader)).filter(

                accessToken -> accessToken.startsWith(BEARER)

        ).map(accessToken -> accessToken.replace(BEARER, ""));
    }

    /**
     * Refresh Token을 request 헤더에서 추출
     * */
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader)).filter(

                refreshToken -> refreshToken.startsWith(BEARER)

        ).map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    /**
     * Access Token으로부터 username을 추출
     * */
    public Optional<String> extractUsername(String accessToken) {
        try {
                return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secret)) // 토큰의 서명의 유효성을 검사하는데 사용할 알고리즘이 있는 JWT verifier builder를 반환
                        .build() // 반환된 빌더로 JWT verifier 생성
                        .verify(accessToken) // Access Token을 검증하고, 유효하지 않으면 예외를 발생시킴
                        .getClaim(USERNAME_CLAIM) // 해당 클레임을 가져옴
                        .asString());
        } catch (Exception e) {
            return Optional.empty();
        }
    }


    /**
     * 응답(reponse) 헤더에 Access Token 넣어줌
     * */
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    /**
     * 응답(reponse) 헤더에 Refresh Token 넣어줌
     * */
    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    }


    /**
     * 토큰의 유효성 검사
     * */
    public boolean isTokenValid(String token){
        try {
            JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
            return true;
        }catch (Exception e){
            new Exception("유효한 토큰이 아닙니다!!");
            return false;
        }
    }

}
```

JWT에 관련된 메서드들이 구현되어 있다. 기본적인 토큰 생성, 토큰 유효성 검사, 토큰에서 정보 추출 등등 중요 기능들을 구현하였다.



 ### LoginSuccessJWTProvideHandler
 ```java
@RequiredArgsConstructor
public class LoginSuccessJWTProvideHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String username = userDetails.getUsername();

        String accessToken = jwtService.createAccessToken(username);
        String refreshToken = jwtService.createRefreshToken();

        jwtService.sendAccessAndRefreshToken(response, accessToken, refreshToken);

        //유저에게 Refresh Token 저장
        userRepository.findByUsername(username).ifPresent(
                user -> user.updateRefreshToken(refreshToken)
        );

    }
}
```

로그인에 성공하게 되면 JWT를 발급해주는 역할을 하는 Handler이다. JWT를 발급해줄 때 Refresh Token을 DB의 user 테이블에 refresh_token 속성에 저장한다.

---

### JwtAuthenticationProcessingFilter
```java
@RequiredArgsConstructor
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
    private final String CHECK_URL = "/login";


    /**
     * 1. 리프레시 토큰이 오는 경우 -> 유효하면 Access Token 재발급후, 필터 진행 X, 바로 return
     *
     * 2. 리프레시 토큰은 없고 Access Token만 있는 경우 -> 유저정보 저장후 필터 계속 진행
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // "/login"으로 들어오는 요청에 대해서는 작동하지 않음
        if(request.getRequestURI().equals(CHECK_URL)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 리프레시 토큰이 없거나 유효하지 않으면 null을 반환
        String refreshToken = jwtService.extractRefreshToken(request)
                                        .filter(jwtService::isTokenValid) // 리프레시 토큰이 유효성이 true 면 통과 아니면 null
                                        .orElse(null);


        //리프레시 토큰이 유효하면 유저정보를 찾아오고, 존재한다면 Access Token 재발급
        if(refreshToken != null){
            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            return;
        }

        // 리프레시 토큰이 없거나 유효하지 않으면 Access Token 검사로직 수행
        checkAccessTokenAndAuthentication(request, response, filterChain);

    }

    private void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        jwtService.extractAccessToken(request).filter(jwtService::isTokenValid).ifPresent(

                accessToken -> jwtService.extractUsername(accessToken).ifPresent(

                        username -> userRepository.findByUsername(username).ifPresent(

                                this::saveAuthentication
                        )
                )
        );

        filterChain.doFilter(request,response);
    }

    private void saveAuthentication(User user) {
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().name())
                .build();

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, authoritiesMapper.mapAuthorities(userDetails.getAuthorities()));

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
    }

    private void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {

        userRepository.findByRefreshToken(refreshToken).ifPresent(
                user -> jwtService.sendAccessToken(response, jwtService.createAccessToken(user.getUsername()))
        );
    }
}
```

JWT를 통한 인증을 처리하는 필터이다. 
OncePerRequestFilter를 상속받은 이유는 인증이나 인가를 위해 1번만 실행되는 필터이기 때문이다. 

각 Case별로 설명한 내용이 로직으로 들어갔다.

---

### SecurityConfig
```java
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final LoginService loginService;
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final JwtService jwtService;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
         http
                    .formLogin().disable()// formLogin 인증방법 비활성화
                    .httpBasic().disable()//httpBasic 인증방법 비활성화(username과 password가 직접 노출되고 암호화 불가)
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                    .and()
                    .authorizeRequests()
                    .antMatchers("/login", "/signUp","/").permitAll() // 로그인, 회원가입, 메인페이지는 인증 없이도 접근 허가
                    .anyRequest().authenticated();

         /**
          * 시큐리티에서 실행되는 필터의 순서가 존재하는데
          * 기존 FormLogin 방식에서는 UsernamePasswordAuthenticationFilter에서 username과 password를 갖고 userpasswordAuthenticationToken 생성
          * 그러나 JSON으로 데이터를 받아와 위 userpasswordAuthenticationToken를 생성하기 위해 JsonUsernamePasswordLoginFilter를 구현함
          * 기존의 시큐리티 필터순서가 LogoutFilter 뒤에 UsernamePasswordAuthenticationFilter가 실행됨
          * 그래서 JsonUsernamePasswordLoginFilter도 LogoutFilter 실행 후에 실행되도록 설정
          * */
        http.addFilterAfter(jsonUsernamePasswordLoginFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), JsonUsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {//2 - AuthenticationManager 등록
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());//PasswordEncoder로는 PasswordEncoderFactories.createDelegatingPasswordEncoder() 사용
        provider.setUserDetailsService(loginService);
        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessJWTProvideHandler loginSuccessJWTProvideHandler(){
        return new LoginSuccessJWTProvideHandler(userRepository, jwtService);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler(){
        return new LoginFailureHandler();
    }

    @Bean
    public JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter(){
        JsonUsernamePasswordAuthenticationFilter jsonUsernamePasswordLoginFilter = new JsonUsernamePasswordAuthenticationFilter(objectMapper);
        jsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        jsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessJWTProvideHandler());
        jsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());

        return jsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter(){
        JwtAuthenticationProcessingFilter jsonUsernamePasswordLoginFilter = new JwtAuthenticationProcessingFilter(userRepository, jwtService);

        return jsonUsernamePasswordLoginFilter;
    }
}
```

jwtAuthenticationProcessingFilter를 Bean으로 등록해주었다.
