package jj.stella.filter.auth;

import java.io.IOException;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
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
import jj.stella.repository.dao.AuthDao;
import jj.stella.util.cookie.CookieUtil;
import jj.stella.util.jwt.TokenUtil;
import jj.stella.util.redis.RedisUtil;

public class AuthLogout implements LogoutSuccessHandler {

	private String JWT_HEADER;
	private String JWT_KEY;
	private String JWT_NAME;
	private String JWT_DOMAIN;
	private String JWT_PATH;
	private String JTI_SERVER;
	private AuthDao authDao;
	RedisTemplate<String, Object> redisTemplate;
	public AuthLogout(
		String JWT_HEADER, String JWT_KEY, String JWT_NAME, String JWT_DOMAIN, String JWT_PATH,
		String JTI_SERVER, AuthDao authDao, RedisTemplate<String, Object> redisTemplate
	) {
		this.JWT_HEADER = JWT_HEADER;
		this.JWT_KEY = JWT_KEY;
		this.JWT_NAME = JWT_NAME;
		this.JWT_DOMAIN = JWT_DOMAIN;
		this.JWT_PATH = JWT_PATH;
		this.JTI_SERVER = JTI_SERVER;
		this.authDao = authDao;
		this.redisTemplate = redisTemplate;
	};
	
	/**
	 * 모든 로그아웃 로직은 여기서 실행
	 */
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth)
		throws IOException, ServletException {
		
		/** Redis 제거 + 쿠키삭제 + Remember Me 제거 */
		clearAuth(request, response);
		
		/** 세션 초기화 */
		clearSession(request);
		
		/** 인증 정보 제거 */
		SecurityContextHolder.clearContext();
		response.sendRedirect("/");
		
	};
	
	/**
	 * 1. 쿠키가 존재할 경우
	 * - 쿠키 제거 + Redis 제거 + Remember Me 제거
	 * 
	 * 2. 쿠키가 존재하지 않는경우
	 * - Redis는 TTL때문에 어차피 n시간 후에 지워짐
	 * - Remember Me는 Device라는 값을 가지고 DB에 저장되어 있는지 확인한 후
	 * 존재한다면 해당 Device의 Remember Me를 제거함 
	 *   > 같은 PC, 같은 환경에서 요청하는 경우에 해당 Device를 가지고 환경을 구분함
	 *   > Device는 로그인 서버의 localStorage에 저장됨
	 *   > 로그인 시도할 때 localStorage에 존재하는 Device값을 가져와서 활용하고, 아니라면 JS로 생성함
	 */
	private void clearAuth(HttpServletRequest request, HttpServletResponse response) {
		
		Cookie[] cookies = request.getCookies();
		if(cookies != null) {
			
			/**
			 * Cookie에서 토큰 추출
			 * Request Header에서 추출하지 않는 이유는
			 * JS나 스크립트로 요청할 수 없게 설정했기 때문.
			 */
			String token = CookieUtil.extractValue(request, cookies, JWT_NAME);
			if(token != null) {
				
				/** 쿠키 제거 */
				CookieUtil.clearCookie(response, cookies, JWT_NAME, JWT_DOMAIN, JWT_PATH);
				
				/** Redis 제거 + Remember Me 제거 */
				clearRedisAndRefreshToken(response, token, cookies);
				
			}
			
		}
		
	};
	
	/** Redis 제거 + Remember Me 제거 */
	private void clearRedisAndRefreshToken(HttpServletResponse response, String token, Cookie[] cookies) {
		
		/** Redis와 Remember Me 초기화를 위한 JTI 조회를 위한 설정 */
		RestTemplate template = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set(JWT_HEADER, JWT_KEY + token);
		
		/**
		 * Redis와 Remember Me 초기화를 위한 JTI 조회
		 * - token에서 jti를 얻고, jti에서 ID와 사용자 기기 식별정보를 추출
		 * - 존재한다면 Redis 제거 + Remember Me 제거
		 *   > 제거하기 위한 데이터가 불러와졌으므로
		 * */
		RefreshTokenDto dto = TokenUtil.getJTI(template, headers, JTI_SERVER);
		if(dto != null) {
			
			/** Redis 제거 */
			RedisUtil.revoke(redisTemplate, dto.getId() + "::" + dto.getDevice());
			
			/** Remember Me - Refresh Token 제거 */
			if(authDao.getRefreshToken(dto) >= 1)
				authDao.delRefreshToken(dto);
			
		}
		
	};
	
	/** 세션 초기화 */
	private void clearSession(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if(session != null)
			session.invalidate();
	};
	
}