package jj.stella.config;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jj.stella.filter.Redirect;
import jj.stella.filter.auth.AuthDetailsSource;
import jj.stella.filter.auth.AuthFailure;
import jj.stella.filter.auth.AuthLogout;
import jj.stella.filter.auth.AuthProvider;
import jj.stella.filter.csrf.Csrf;
import jj.stella.filter.csrf.CsrfHandler;
import jj.stella.filter.csrf.CsrfRepository;
import jj.stella.filter.jwt.JwtIssue;
import jj.stella.properties.AuthProperties;
import jj.stella.properties.ServerProperties;
import jj.stella.repository.dao.AuthDao;
import jj.stella.util.auth.AuthUtil;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	private final AuthProperties authProperties;
	private final ServerProperties serverProperties;
	public SecurityConfig(AuthProperties authProperties, ServerProperties serverProperties) {
		this.authProperties = authProperties;
		this.serverProperties = serverProperties;
	};
	
	private static final String[] WHITE_LIST = {
		"/resources/**", "/static/**", "/favicon.ico", "/", "/logout"
	};
	
	/**
	 * JwtAuthenticationFilter와 같은 Filter에 직접 추가하는 경우
	 * 생명주기 밖에서 생성되기 때문에 null로 초기화 됨. 
	 */
	@Autowired
	private AuthDao authDao;
	@Autowired
	private AuthUtil authUtil;
	
	/** 사용자 인증 */
	@Autowired
	private AuthProvider authProvider;
	
	/**
	 * JWT 발급을 위한 Redis 설정
	 * - jti에 사용자 기기 식별번호를 넣고 TTL 설정
	 * - 계정 비활성화 할 때 redis도 사용자 기기 식별번호로 파기하면 됨.
	 * - 검증할 때 토큰과 Redis의 jti를 비교
	 */
	@Autowired
	private RedisTemplate<String, String> redisTemplate;
	
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		String JWT_HEADER = authProperties.getJwt().getHeader();
		String JWT_KEY = authProperties.getJwt().getKey();
		String JWT_NAME = authProperties.getJwt().getName();
		String JWT_ISSUER = authProperties.getJwt().getIssuer();
		String JWT_AUDIENCE = authProperties.getJwt().getAudience();
		String JWT_REFRESH_ISSUER = authProperties.getJwt().getRefresh().getIssuer();
		String JWT_REFRESH_AUDIENCE = authProperties.getJwt().getRefresh().getAudience();
		String JWT_DOMAIN = authProperties.getJwt().getDomain();
		String JWT_PATH = authProperties.getJwt().getPath();
		String JWT_EXPIRED = authProperties.getJwt().getExpired();
		String JWT_ENCRYPT_SIGN = authProperties.getJwt().getEncrypt().getSign();
		String JWT_ENCRYPT_TOKEN = authProperties.getJwt().getEncrypt().getToken();
		String JWT_ENCRYPT_REFRESH_SIGN = authProperties.getJwt().getEncrypt().getRefresh().getSign();
		String JWT_ENCRYPT_REFRESH_TOKEN = authProperties.getJwt().getEncrypt().getRefresh().getToken();
		
		String CSRF_NAME = authProperties.getCsrf().getName();
		String CSRF_PARAMETER = authProperties.getCsrf().getParameter();
		String CSRF_HEADER = authProperties.getCsrf().getHeader();
		
		String AUTH_SERVER = serverProperties.getAuth();
		String JTI_SERVER = serverProperties.getJti();
		String HOME_SERVER = serverProperties.getHome();
		String ORIGIN_IP_API = serverProperties.getApi().getOriginIp();
		
		return http
			.headers(headers ->
				headers
					.frameOptions(frame -> frame.sameOrigin()
			))
			.cors(cors -> corsConfigurationSource())
			.csrf(csrf ->
				csrf
					// XSRF-TOKEN 발급 ( 쿠키저장 )
					.csrfTokenRepository(new CsrfRepository(CSRF_NAME, CSRF_PARAMETER, CSRF_HEADER))
					.csrfTokenRequestHandler(new CsrfHandler(CSRF_PARAMETER))
			)
			.formLogin(form ->
				form
					.loginPage("/")
					.loginProcessingUrl("/loginproc")
					// 인증할 때 직접만든 AuthProvider를 이용해야하는데
					// IP나 User-Agent를 접근하려는 HttpServletRequest를 사용할 수 없어서
					// 해당 라인을 추가함.
					.authenticationDetailsSource(new AuthDetailsSource(ORIGIN_IP_API))
					// 성공 후 처리는 JwtIssue에서 진행함
					// - .addFilterAfter(new JwtIssue(...), UsernamePasswordAuthenticationFilter.class)
					//  > UsernamePasswordAuthenticationFilter.class 이후 = 로그인 성공 이후
					//  > .successHandler(new AuthSuccess(LOGIN_SERVER)) 사용 안함
					.failureHandler(new AuthFailure(authDao, authUtil))
			)
			.logout(logout ->
				logout
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
					.logoutSuccessHandler(new AuthLogout(
						JWT_HEADER, JWT_KEY, JWT_NAME, JWT_DOMAIN, JWT_PATH,
						JTI_SERVER, authDao, redisTemplate
					))
			)
			.authorizeHttpRequests(auth ->
				auth
					// CorsUtil PreFlight 요청은 인증처리 하지 않겠다는 의미
					// CorsUtil PreFlight에는 Authorization 헤더를 줄 수 없으므로 401 응답을 해선안된다.
					.requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
					.requestMatchers(getRequestMatchers(WHITE_LIST)).permitAll()
					.anyRequest().authenticated()
			)
			.addFilterBefore(new Redirect(
				JWT_HEADER, JWT_KEY, JWT_NAME, JWT_ISSUER, JWT_AUDIENCE, JWT_EXPIRED,
				JWT_DOMAIN, JWT_PATH, JTI_SERVER,
				encryptSignKey(JWT_ENCRYPT_SIGN), encryptTokenKey(JWT_ENCRYPT_TOKEN),
				AUTH_SERVER, HOME_SERVER, authDao, redisTemplate
			), UsernamePasswordAuthenticationFilter.class)
			// 로그인, 로그아웃 이후 응답헤더에 XSRF-TOKEN을 보내기 위함. ( 갱신 )
			.addFilterAfter(new Csrf(), CsrfFilter.class)
			// 로그인 성공 후 Jwt 토큰 발급
			.addFilterAfter(new JwtIssue(
				JWT_NAME, JWT_ISSUER, JWT_AUDIENCE,
				JWT_REFRESH_ISSUER, JWT_REFRESH_AUDIENCE, JWT_DOMAIN, JWT_PATH, JWT_EXPIRED,
				encryptSignKey(JWT_ENCRYPT_SIGN), encryptTokenKey(JWT_ENCRYPT_TOKEN),
				encryptSignKey(JWT_ENCRYPT_REFRESH_SIGN), encryptTokenKey(JWT_ENCRYPT_REFRESH_TOKEN),
				HOME_SERVER, authDao, redisTemplate
			), UsernamePasswordAuthenticationFilter.class)
			.sessionManagement(session -> session 
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.sessionFixation().changeSessionId()
				.maximumSessions(7)
				.maxSessionsPreventsLogin(false)
				.expiredUrl("/")
			).build();
	};
	
	/** 비밀번호 암호화 ( 단방향 복호화 불가능 ) */
	@Bean
	public PasswordEncoder encoder() {
		
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
		
	};
	
	/** 사용자 인증 */
	@Bean
	public AuthenticationManager AuthenticationManager(AuthenticationConfiguration auth) throws Exception {
		return auth.getAuthenticationManager();
	};
	@Autowired
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authProvider);
	};
	
	/** CORS 정책 수립 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		
		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.addAllowedOriginPattern("*://*.dev.st2lla.co.kr");
		corsConfig.addAllowedOriginPattern("*://*.intra.st2lla.co.kr");
		corsConfig.setAllowCredentials(true);
		corsConfig.setMaxAge(3600L);
		corsConfig.setAllowedMethods(Arrays.asList("GET", "POST"));
		corsConfig.setAllowedHeaders(
			Arrays.asList(
				"Content-Type",
				"X-XSRF-TOKEN",
				"Authorization",
				"User-Agent",
				"Content-Length",
				"X-Requested-With",
				
				"REISSUE-ID",
				"REISSUE-IP",
				"REISSUE-AGENT",
				"REISSUE-DEVICE"
			)
		);
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);
		
		return source;
		
	};
	
	/** session control */
	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	};
	
	// 서명과 토큰의 암호화를 위한 Key 설정
	private Key encryptSignKey(String key) {
		
		// Base64 인코딩된 문자열을 디코드하여 바이트 배열로 변환
		byte[] decodedKey = Base64.getDecoder().decode(key);
		
		// 바이트 배열을 사용하여 SecretKey 객체 생성
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA256");
		
	};
	private Key encryptTokenKey(String key) {
		
		byte[] decodedKey = Base64.getDecoder().decode(key);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		
	};
	
	private RequestMatcher[] getRequestMatchers(String... str) {
		return Arrays.stream(str)
			.map(AntPathRequestMatcher::new)
			.toArray(RequestMatcher[]::new);
	};
	
}