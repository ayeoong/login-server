package jj.stella.filter.jwt;

import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.ResultDto;
import jj.stella.filter.auth.AuthDetails;
import jj.stella.repository.dao.AuthDao;
import jj.stella.util.auth.AuthUtil;
import jj.stella.util.cookie.CookieUtil;
import jj.stella.util.jwt.RedirectUtil;
import jj.stella.util.jwt.TokenUtil;
import jj.stella.util.redis.RedisUtil;

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
	private AuthUtil authUtil;
	private RedisTemplate<String, Object> redisTemplate;
	public JwtIssue(
		String JWT_NAME, String JWT_ISSUER, String JWT_AUDIENCE,
		String JWT_REFRESH_ISSUER, String JWT_REFRESH_AUDIENCE, String JWT_DOMAIN, String JWT_PATH, String JWT_EXPIRED,
		Key JWT_ENCRYPT_SIGN, Key JWT_ENCRYPT_TOKEN,
		Key JWT_ENCRYPT_REFRESH_SIGN, Key JWT_ENCRYPT_REFRESH_TOKEN, 
		String HOME_SERVER, AuthDao authDao, AuthUtil authUtil, RedisTemplate<String, Object> redisTemplate
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
		this.authUtil = authUtil;
		this.redisTemplate = redisTemplate;
	};
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		/** 로그인이 성공했을 때 로직 실행 */
		if(auth != null && auth.isAuthenticated()) {
			
			String username = auth.getName();
			AuthDetails details = (AuthDetails) auth.getDetails();
			
			/** 로그인 성공 = 인증토큰 발급 + 세팅( JWE = 암호화된 JWT, Redis & Cookie에 저장 ) */
			issueAuthTokenAndSet(response, username, details);
			
			/** 로그인 성공 = 사용자가 자동로그인을 설정한 경우 Refresh Token 발급 + 세팅( JWE = 암호화된 JWT, DB에 저장 ) */
			if(details.isRememberMe())
				issueRefreshTokenAndSet(username, details);

			/** 로그인 결과 저장 - 성공 */
			authDao.regLoginResult(new ResultDto(
				"success", authUtil.encryptName(username), ((AuthDetails) details).getIp()
			));
			
			/**
			 * 어디로 Redirect 할 것인지 설정
			 * Axios로 요청이 왔기 때문에 경로를 설정후 반환해야 함.
			 * ( sendRedirect가 동작하지 않음. )
			 * */ 
			redirect(request, response);
			
			/** 중요. / 이후 FilterChain이 동작하지 않도록 여기서 반환 */
			return;
			
		}
		
		chain.doFilter(request, response);
		
	};
	
	/** 인증토큰 발급 + 세팅( JWE = 암호화된 JWT, Redis & Cookie에 저장 ) */
	private void issueAuthTokenAndSet(HttpServletResponse response, String id, AuthDetails details) {
		try {
			
			/** 인증토큰 발급( JWE = 암호화된 JWT ) */
			String JWE_TOKEN = TokenUtil.issueJWE(
				id, details,
				JWT_ENCRYPT_SIGN, JWT_ENCRYPT_TOKEN,
				JWT_ISSUER, JWT_AUDIENCE, JWT_EXPIRED
			);
			
			/** 인증토큰의 경우 발급하자마자 jti( id::사용자 기기 식별번호 )를 활용해 Redis에 저장함. */
			String jti = id + "::" + details.getDevice();
			RedisUtil.save(redisTemplate, jti, "true", JWT_EXPIRED, TimeUnit.MILLISECONDS);
			
			/**
			 * 만들어진 JWE 토큰을 Cookie에 세팅
			 * - 쿠키의 유효기간은 반년으로 설정하고
			 * 1. 검증요청( 검증서버로 /validate 요청 ) 혹은
			 * 2. 인증 재발급 요청( 검증서버에서 로그인서버로 /refresh 요청 )
			 * 이 성공하는 경우 요청을 보낸 서버에서 쿠키의 생명을 연장함
			 * */
			CookieUtil.setCookie(response, JWT_NAME, JWE_TOKEN, JWT_DOMAIN, JWT_PATH, (int) (((JWT_EXPIRED * 8 * 365) / 2) / 1000));
			
		} catch(JOSEException e) {
			SecurityContextHolder.clearContext();
			throw new RuntimeException("JWT Issue and Encryption Error: ", e);
		}
	};
	
	/** Refresh Token 발급 + 세팅( JWE = 암호화된 JWT, DB에 저장 ) */
	private void issueRefreshTokenAndSet(String id, AuthDetails details) {
		try {
			
			RefreshTokenDto dto = new RefreshTokenDto();
			dto.setId(id);
			dto.setDevice(details.getDevice());
			
			/** Refresh Token 발급( JWE = 암호화된 JWT ) */
			dto.setToken(TokenUtil.issueJWE(id, details,
				JWT_ENCRYPT_REFRESH_SIGN, JWT_ENCRYPT_REFRESH_TOKEN,
				JWT_REFRESH_ISSUER, JWT_REFRESH_AUDIENCE, JWT_EXPIRED * 8 * 365
			));
			
			/** Refresh Token DB저장 */
			authDao.regRefreshToken(dto);
			
		} catch(JOSEException e) {
			SecurityContextHolder.clearContext();
			throw new RuntimeException("JWT Issue and Encryption Error: ", e);
		}
	};
	
	/**
	 * 어디로 Redirect 할 것인지 설정
	 * Axios로 요청이 왔기 때문에 경로를 설정후 반환해야 함.
	 * ( sendRedirect가 동작하지 않음. )
	 * 즉, 기존에 작성했던 AuthSuccess 유틸의 로직을 여기서 동작하게 함.
	 * */ 
	private void redirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		String referer = request.getParameter("referer");
		
		/** Redirect 경로 검증 */
		String redirectURL = RedirectUtil.validateReferer(referer)? referer:HOME_SERVER;
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
	
}