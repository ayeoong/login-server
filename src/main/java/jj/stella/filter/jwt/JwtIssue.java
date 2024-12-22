package jj.stella.filter.jwt;

import java.io.IOException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.ResultDto;
import jj.stella.filter.auth.AuthDetails;
import jj.stella.repository.dao.AuthDao;

public class JwtIssue extends OncePerRequestFilter {
	
	private String JWT_NAME;
	private String JWT_ISSUER;
	private String JWT_AUDIENCE;
	private String JWT_REFRESH_ISSUER;
	private String JWT_REFRESH_AUDIENCE;
	private String JWT_DOMAIN;
	private String JWT_PATH;
	private long JWT_EXPIRED;
	private Key JWT_ENCRYPT_SIGN;
	private Key JWT_ENCRYPT_TOKEN;
	private Key JWT_ENCRYPT_REFRESH_SIGN;
	private Key JWT_ENCRYPT_REFRESH_TOKEN;
	private String HOME_SERVER;
	private AuthDao authDao;
	private RedisTemplate<String, String> redisTemplate;
	public JwtIssue(
		String JWT_NAME, String JWT_ISSUER, String JWT_AUDIENCE,
		String JWT_REFRESH_ISSUER, String JWT_REFRESH_AUDIENCE, String JWT_DOMAIN, String JWT_PATH, String JWT_EXPIRED,
		Key JWT_ENCRYPT_SIGN, Key JWT_ENCRYPT_TOKEN,
		Key JWT_ENCRYPT_REFRESH_SIGN, Key JWT_ENCRYPT_REFRESH_TOKEN, 
		String HOME_SERVER, AuthDao authDao, RedisTemplate<String, String> redisTemplate
	) {
		this.JWT_NAME = JWT_NAME;
		this.JWT_ISSUER = JWT_ISSUER;
		this.JWT_AUDIENCE = JWT_AUDIENCE;
		this.JWT_REFRESH_ISSUER = JWT_REFRESH_ISSUER;
		this.JWT_REFRESH_AUDIENCE = JWT_REFRESH_AUDIENCE;
		this.JWT_DOMAIN = JWT_DOMAIN;
		this.JWT_PATH = JWT_PATH;
		this.JWT_EXPIRED = Long.parseLong(JWT_EXPIRED);
		this.JWT_ENCRYPT_SIGN = JWT_ENCRYPT_SIGN;
		this.JWT_ENCRYPT_TOKEN = JWT_ENCRYPT_TOKEN;
		this.JWT_ENCRYPT_REFRESH_SIGN = JWT_ENCRYPT_REFRESH_SIGN;
		this.JWT_ENCRYPT_REFRESH_TOKEN = JWT_ENCRYPT_REFRESH_TOKEN;
		this.HOME_SERVER = HOME_SERVER;
		this.authDao = authDao;
		this.redisTemplate = redisTemplate;
	};
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if(auth != null && auth.isAuthenticated()) {
			
			String id = auth.getName();
			AuthDetails details = (AuthDetails) auth.getDetails();
			String ip = ((AuthDetails) details).getIp();
			
			/** 로그인 성공 시 인증토큰 발급 + 세팅 ( 암호화된 JWT = JWE / Cookie And Redis 세팅 ) */
			issueAuthTokenAndSet(response, id, details);
			
			/** 로그인 성공 + 사용자가 자동로그인을 설정한 경우 Refresh Token 발급 + 세팅 ( 암호화된 JWT + JWE / DB ) */
			if(details.isRememberMe())
				issueRefreshTokenAndSet(id, details);

			/** 로그인 결과 저장 - 성공 */
			authDao.regLoginResult(new ResultDto("success", id, ip));
			
			/**
			 * 어디로 Redirect 할 것인지 설정
			 * Axios로 요청이 왔기 때문에 경로를 설정후 반환해야 함.
			 * ( sendRedirect가 동작하지 않음. )
			 * */ 
			redirectToOrigin(request, response);
			
			/** 중요. / 이후 FilterChain이 동작하지 않도록 여기서 반환 */
			return;
			
		}
		
		chain.doFilter(request, response);
		
	};
	
	/** 인증토큰 발급 + 세팅 ( 암호화된 JWT = JWE / Cookie And Redis 세팅 ) */
	private void issueAuthTokenAndSet(HttpServletResponse response, String id, AuthDetails details) {
		try {
			
			/** 인증토큰 발급 ( 암호화된 JWT = JWE ) */
			/** 마지막 false로 Refresh Token인지 여부 판단 */
			/** 인증토큰의 경우 발급하자마자 jti( id::사용자 기기 식별번호 )를 활용해 Redis에 저장함. */
			String token = issueAndEncryptToken(id, details, false);
			
			/** Cookie 세팅 */
			setCookie(token, response);
			
		} catch (JOSEException e) {
			SecurityContextHolder.clearContext();
			throw new RuntimeException("JWT Issue and Encryption Error: ", e);
		}
	};
	
	/** Refresh Token 발급 + 세팅 ( 암호화된 JWT = JWE / DB ) */
	private void issueRefreshTokenAndSet(String id, AuthDetails details) {
		try {
			
			RefreshTokenDto dto = new RefreshTokenDto();
			dto.setId(id);
			dto.setDevice(details.getDevice());
			
			/** Refresh Token 발급 ( 암호화된 JWT = JWE ) */
			/** 마지막 true로 Refresh Token인지 여부 판단 */
			dto.setToken(issueAndEncryptToken(id, details, true));
			
			/** Refresh Token DB저장 */
			authDao.regRefreshToken(dto);
			
		} catch (JOSEException e) {
			SecurityContextHolder.clearContext();
			throw new RuntimeException("JWT Issue and Encryption Error: ", e);
		}
	};
	
	/** Token 발급 로직 실행 */
	private String issueAndEncryptToken(String id, AuthDetails details, boolean isRefresh) throws JOSEException {
		
		/**
		 * JWT 토큰 발급
		 * Redis 저장 ( 인증토큰의 경우 - Remember Me( Refresh Token )이 아닌 경우 )
		 */
		JWTClaimsSet jwt = issueJwt(id, details, isRefresh);
		
		/** JWT 서명 */
		SignedJWT token = signJwt(jwt, !isRefresh? JWT_ENCRYPT_SIGN:JWT_ENCRYPT_REFRESH_SIGN);
		
		/** JWT 암호화 = JWE */
		JWEObject jwe = encryptJwt(token, !isRefresh? JWT_ENCRYPT_TOKEN:JWT_ENCRYPT_REFRESH_TOKEN);
		
		return jwe.serialize();
		
	};
	
	/** JWT 토큰 발급 */
	private JWTClaimsSet issueJwt(String id, AuthDetails details, boolean isRefresh) {
		
		Date now = new Date();
		
		String jti = id + "::" + details.getDevice();
		long expired = !isRefresh? JWT_EXPIRED:(JWT_EXPIRED * 8 * 365);
		String issuer = !isRefresh? JWT_ISSUER:JWT_REFRESH_ISSUER;
		String audience = !isRefresh? JWT_AUDIENCE:JWT_REFRESH_AUDIENCE;
		
		/** 인증토큰의 경우 jti로 Redis에 저장 ( 존재유무만 판단하면 됨 ) */
		if(!isRefresh)
			storeJTIInRedis(jti, JWT_EXPIRED);
		
		return new JWTClaimsSet.Builder()
				.issuer(issuer)
				.subject(id)
				.audience(audience)
				.jwtID(jti)
				.expirationTime(new Date(now.getTime() + expired))
				.claim("ip", details.getIp())
				.claim("agent", details.getAgent())
				.claim("device", details.getDevice())
				.build();
		
	};
	
	/** 인증토큰의 경우 jti로 Redis에 저장 ( 존재유무만 판단하면 되기 때문에 값은 "true"로 통일 ) */
	private void storeJTIInRedis(String jti, long expired) {
		ValueOperations<String, String> ops = redisTemplate.opsForValue();
		ops.set(jti, "true", expired, TimeUnit.MILLISECONDS);
	};
	
	/** JWT 서명 */
	private SignedJWT signJwt(JWTClaimsSet jwt, Key key) throws JOSEException {
		
		SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwt);
		signedJwt.sign(new MACSigner(key.getEncoded()));
		
		return signedJwt;
		
	};
	
	/** JWT 암호화 = JWE */
	private JWEObject encryptJwt(SignedJWT token, Key key) throws JOSEException {
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
			new Payload(token)
		);
		
		jweObject.encrypt(new DirectEncrypter(key.getEncoded()));
		return jweObject;
		
	};
	
	/** JWE Cookie 세팅 */
	private void setCookie(String token, HttpServletResponse response) {
		
		Cookie cookie = new Cookie(JWT_NAME, token);
		
		/**
		 * 쿠키의 유효기간은 반년으로 설정하고
		 * "검증서버의 '/validate'"가 성공하거나
		 * "검증서버에서 로그인서버로의 재발급요청 '/refresh'"이 성공하면
		 * "검증서버에서" 쿠키의 생명을 연장.
		 * */
		cookie.setDomain(JWT_DOMAIN);
		cookie.setMaxAge((int) (((JWT_EXPIRED * 8 * 365) / 2) / 1000));
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath(JWT_PATH);
		
		response.addCookie(cookie);
		
	};
	
	/**
	 * 어디로 Redirect 할 것인지 설정
	 * Axios로 요청이 왔기 때문에 경로를 설정후 반환해야 함.
	 * ( sendRedirect가 동작하지 않음. )
	 * 즉, 기존에 작성했던 AuthSuccess 유틸의 로직을 여기서 동작하게 함.
	 * */ 
	private void redirectToOrigin(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		String referer = request.getParameter("referer");
		
		/** Redirect 경로 검증 */
		String redirectURL = validateReferer(referer)? referer:HOME_SERVER;
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.setStatus(HttpServletResponse.SC_OK);
		
		Map<String, Object> map = new HashMap<>();
		map.put("redirect", redirectURL);
		
		ObjectMapper mapper = new ObjectMapper();
		String result = mapper.writeValueAsString(map);
		response.getWriter().write(result);
		response.getWriter().flush();
		
	};
	
	/** Redirect 경로 확인 */
	private boolean validateReferer(String referer) {
		return referer != null && (
			referer.startsWith("http://localhost")
			|| referer.startsWith("http://dev.st2lla.co.kr")
			|| referer.startsWith("https://dev.st2lla.co.kr")
			|| referer.startsWith("http://intra.st2lla.co.kr")
			|| referer.startsWith("https://intra.st2lla.co.kr")
		) && !referer.startsWith("http://localhost:8080");
	};
	
}