package jj.stella.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	private static final String[] WHITE_LIST = {
		"/resources/**", "/favicon.ico", "/", "/logout"
	};
	
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		return http
		.headers(headers ->
			headers
				.frameOptions(frame -> frame.sameOrigin()
		))
		.cors(cors -> corsConfigurationSource())
		.csrf(csrf -> csrf.disable())
		.formLogin(form ->
			form
				.loginPage("/")
				.loginProcessingUrl("/loginproc")
		)
		.authorizeHttpRequests(auth ->
			auth
				// CorsUtil PreFlight 요청은 인증처리 하지 않겠다는 의미
				// CorsUtil PreFlight에는 Authorization 헤더를 줄 수 없으므로 401 응답을 해선안된다.
				.requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
				.requestMatchers(getRequestMatchers(WHITE_LIST)).permitAll()
				.anyRequest().authenticated()
		)
		.sessionManagement(session -> session 
			.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
			.sessionFixation().changeSessionId()
			.maximumSessions(7)
			.maxSessionsPreventsLogin(false)
			.expiredUrl("/")
		)
		.build();
	}
	
	/** 비밀번호 암호화 ( 단방향 복호화 불가능 ) */
	@Bean
	public PasswordEncoder encoder() {
		
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
		
	}
	
	/** 사용자 인증 */
	@Bean
	public AuthenticationManager AuthenticationManager(AuthenticationConfiguration auth) throws Exception {
		return auth.getAuthenticationManager();
	}
//	@Autowired
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.authenticationProvider(authProvider);
//	}
	
	/** CORS 정책 수립 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		
		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowCredentials(true);
		corsConfig.setMaxAge(3600L);
		corsConfig.setAllowedMethods(Arrays.asList("GET", "POST"));
		corsConfig.setAllowedHeaders(
			Arrays.asList(
				"Content-Type", "X-XSRF-TOKEN", "Authorization",
				"User-Agent", "Content-Length", "X-Requested-With"
			)
		);
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);
		
		return source;
		
	}
	
	/** session control */
	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}
	
	private RequestMatcher[] getRequestMatchers(String... str) {
		return Arrays.stream(str)
			.map(AntPathRequestMatcher::new)
			.toArray(RequestMatcher[]::new);
	}
	
}