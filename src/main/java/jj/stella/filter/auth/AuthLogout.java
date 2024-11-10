package jj.stella.filter.auth;

import java.io.IOException;
import java.util.Arrays;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.repository.dao.CommonDao;

public class AuthLogout implements LogoutSuccessHandler {

	private String JWT_HEADER;
	private String JWT_KEY;
	private String JWT_NAME;
	private String JWT_DOMAIN;
	private String JWT_PATH;
	private String JTI_SERVER;
	private CommonDao commonDao;
	RedisTemplate<String, String> redisTemplate;
	public AuthLogout(
		String JWT_HEADER, String JWT_KEY, String JWT_NAME, String JWT_DOMAIN, String JWT_PATH,
		String JTI_SERVER, CommonDao commonDao, RedisTemplate<String, String> redisTemplate
	) {
		this.JWT_HEADER = JWT_HEADER;
		this.JWT_KEY = JWT_KEY;
		this.JWT_NAME = JWT_NAME;
		this.JWT_DOMAIN = JWT_DOMAIN;
		this.JWT_PATH = JWT_PATH;
		this.JTI_SERVER = JTI_SERVER;
		this.commonDao = commonDao;
		this.redisTemplate = redisTemplate;
	};
	
	/**
	 * 모든 로그아웃 로직은 여기서 실행
	 */
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth)
		throws IOException, ServletException {
		
		// 쿠키삭제 + Remember Me 제거 + Redis 제거
		invalidateAuth(request, response);
		
		// 세션 무효화
		invalidateSession(request);
		
		// 인증 정보 클리어
		SecurityContextHolder.clearContext();
		response.sendRedirect("/");
		
	};
	
	/**
	 * 쿠키삭제 + Remember Me 제거 + Redis 제거
	 * 쿠키를 강제로 지운상태라면 어차피 n시간후에 TTL때문에 사라짐
	 * 그리고 재발급하더라도 localStorage의 값이 같기때문에 상관없음.
	 * 마음이 편하려고 추가한 로직임.
	 * 쿠키가 없으면 Remember Me를 지울 수 없기 때문에 생성된 날짜 기준 프로시저로 삭제함.
	 */
	private void invalidateAuth(HttpServletRequest request, HttpServletResponse response) {
		
		Cookie[] cookies = request.getCookies();
		if(cookies != null) {
			
			/** Cookie에서 토큰 추출 */
			String token = extractToken(request);
			if(token != null)
				clearAuth(response, token, cookies);
			
		}
		
	};
	
	/**
	 * Cookie에서 토큰 추출
	 * Request Header에서 추출하지 않는 이유는
	 * JS나 스크립트로 요청할 수 없게 설정했기 때문.
	 */
	private String extractToken(HttpServletRequest request) {
		
//		String token = request.getHeader(JWT_HEADER);
//		if(token != null && token.startsWith(JWT_KEY))
//			return token.substring(JWT_KEY.length());
		if(request.getCookies() != null) {
			return Arrays.stream(request.getCookies())
					.filter(cookie -> JWT_NAME.equals(cookie.getName()))
					.findFirst()
					.map(Cookie::getValue)
					.orElse(null);
		}
		
		return null;
		
	};
	
	/**
	 * 쿠키삭제 + Remember Me 제거 + Redis 제거
	 */
	private void clearAuth(HttpServletResponse response, String token, Cookie[] cookies) {
		
		/** 쿠키 제거 */
		clearCookie(response, cookies);
		
		RestTemplate template = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set(JWT_HEADER, JWT_KEY + token);
		
		/** token에서 jti를 얻고, jti에서 ID와 사용자 기기 식별정보를 추출 */
		RefreshTokenDto dto = extractTokenData(template, headers);
		if(dto != null) {
			/** Redis 제거 */
			clearRedis(dto.getId() + "::" + dto.getDevice());
			/** Remember Me - Refresh Token 제거 */
			clearRefreshToken(dto);
		}
		
	};
	
	/** token에서 jti를 얻고, jti에서 ID와 사용자 기기 식별정보를 추출 */
	private RefreshTokenDto extractTokenData(RestTemplate template, HttpHeaders headers) {
		
		RefreshTokenDto dto = new RefreshTokenDto();
		HttpEntity<String> entity = new HttpEntity<>("", headers);
		ResponseEntity<String> res = template.exchange(JTI_SERVER, HttpMethod.GET, entity, String.class);
		
		String[] split = res.getBody().split("::");
		if(split.length < 2)
			return null;
		
		dto.setId(split[0]);
		dto.setDevice(split[1]);
		
		return dto;
		
	};
	
	/** Redis 제거 */
	private void clearRedis(String key) {
		redisTemplate.delete(key);
	};
	
	/** Remember Me - Refresh Token 제거 */
	private void clearRefreshToken(RefreshTokenDto dto) {
		if(commonDao.getRefreshToken(dto) >= 1)
			commonDao.removeRefreshToken(dto);
	};
	
	/** 쿠키 제거 */
	private void clearCookie(HttpServletResponse response, Cookie[] cookies) {
		Arrays.stream(cookies)
			.filter(cookie -> JWT_NAME.equals(cookie.getName()))
			.forEach(cookie -> {
				
				cookie.setDomain(JWT_DOMAIN);
				cookie.setValue("");
				cookie.setMaxAge(0);
				cookie.setPath(JWT_PATH);
				
				response.addCookie(cookie);
				
			});
	};
	
	/** 세션 초기화 */
	private void invalidateSession(HttpServletRequest request) {
		
		HttpSession session = request.getSession(false);
		if(session != null)
			session.invalidate();
		
	};
	
}