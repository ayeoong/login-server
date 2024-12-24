package jj.stella.filter;

import java.io.IOException;
import java.security.Key;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.jose.JOSEException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.ReissueDto;
import jj.stella.entity.dto.ResultDto;
import jj.stella.repository.dao.AuthDao;
import jj.stella.util.auth.AuthUtil;
import jj.stella.util.cookie.CookieUtil;
import jj.stella.util.jwt.RedirectUtil;
import jj.stella.util.jwt.TokenUtil;
import jj.stella.util.redis.RedisUtil;

public class Redirect extends OncePerRequestFilter {
	
	private static final String USER_AGENT = "User-Agent";
//	private static final String XHR_HEADER = "X-Requested-With";
//	private static final String XHR_HEADER_VALUE = "XMLHttpRequest";
//	private static final String ACCEPT_HEADER = "Accept";
	
	private String JWT_HEADER;
	private String JWT_KEY;
	private String JWT_NAME;
	private String JWT_ISSUER;
	private String JWT_AUDIENCE;
	private String JWT_DOMAIN;
	private String JWT_PATH;
	private String JTI_SERVER;
	private long JWT_EXPIRED;
	private Key JWT_ENCRYPT_SIGN;
	private Key JWT_ENCRYPT_TOKEN;
	private String AUTH_SERVER;
	private String HOME_SERVER;
	private AuthDao authDao;
	private AuthUtil authUtil;
	RedisTemplate<String, Object> redisTemplate;
	public Redirect(
		String JWT_HEADER, String JWT_KEY, String JWT_NAME,
		String JWT_ISSUER, String JWT_AUDIENCE, String JWT_EXPIRED,
		String JWT_DOMAIN, String JWT_PATH, String JTI_SERVER,
		Key JWT_ENCRYPT_SIGN, Key JWT_ENCRYPT_TOKEN, 
		String AUTH_SERVER, String HOME_SERVER, AuthDao authDao,
		AuthUtil authUtil, RedisTemplate<String, Object> redisTemplate
	) {
		this.JWT_HEADER = JWT_HEADER;
		this.JWT_KEY = JWT_KEY;
		this.JWT_NAME = JWT_NAME;
		this.JWT_ISSUER = JWT_ISSUER;
		this.JWT_AUDIENCE = JWT_AUDIENCE;
		this.JWT_DOMAIN = JWT_DOMAIN;
		this.JWT_PATH = JWT_PATH;
		this.JTI_SERVER = JTI_SERVER;
		this.JWT_EXPIRED = Long.parseLong(JWT_EXPIRED);
		this.JWT_ENCRYPT_SIGN = JWT_ENCRYPT_SIGN;
		this.JWT_ENCRYPT_TOKEN = JWT_ENCRYPT_TOKEN;
		this.AUTH_SERVER = AUTH_SERVER;
		this.HOME_SERVER = HOME_SERVER;
		this.authDao = authDao;
		this.authUtil = authUtil;
		this.redisTemplate = redisTemplate;
	}
	
	/**
	 * 로그아웃 로직이 실행된 "후" 아래 로직이 동작함.
	 * 즉, /logout 요청 시 AuthLogout에서 모든 로그아웃에 필요한 세션, 쿠키, 인증정보 등등을 무효화를 담당하고
	 * 로그아웃 이후 Redirect된 경로 "/"가 아래로직으로 실행됨.
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		
		/**
		 * resources 이하의 모든경로는 permitAll이기 때문에 검증요청 하지않음.
		 * 즉, "/resources/**"는 모두 허용하며
		 * 위 경우를 제외하고 "/" 이외의 경로로 접근하게 되면, Spring Security 설정으로 "/"에 보내도록 함.
		 * "/" 경로는 토큰 유무와 유효성 검사를 진행해서 Redirect하는 곳을 판단함.
		 * 
		 * 해당로직을 위해 리소스 경로는 Spring Security 로직 진행
		 */
		String path = request.getRequestURI();
		if(RedirectUtil.validateSkipPath(path)) {
			chain.doFilter(request, response);
			return;
		}
		
		/**
		 * 검증서버에서 "/refresh" 경로로 인증토큰 재발급 요청이 들어온 경우
		 * 인터넷 주소창이 /refresh 그냥 입력하는 경우는 걸러냄.
		 */
		if(RedirectUtil.validateRefreshPath(request, path)) {
			/**
			 * 조건에 맞다면 재발급 로직 실행
			 * 재발급 후 Cookie 갱신, 저장 / Redis 저장을 하지 않는 이유는
			 * 검증서버로 반환한 후 검증로직을 거치고
			 * 그 후에 처리하기 위함.
			 * 애시당초 여기서 Redis는 저장이 되도, 검증서버에서 RestTemplate으로 요청이 왔기 때문에
			 * response로 쿠키를 설정할 수가 없음. ( response로 반환해야 함. )
			 * */
			reissueAuthToken(request, response);
			return;
		}
		
		redirect(request, response, chain);
		
	};
	
	/**
	 * 요청서버에서 직접 설정한 REISSUE-* 헤더 n개가 모두 존재하는 경우
	 * 인증토큰 재발급 후 검증서버로 반환
	 * */
	private void reissueAuthToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		/** 재발급에 필요한 정보를 요청 Header에서 추출 */
		/**
		 * 요청 Header에서 값을 뽑아낸 후 Dto로 변환해서 Return
		 * 요청 Header에 값이 없는 경우는 isRefreshPath에서 사전에 걸러내기 때문에
		 * 해당 경우는 존재할 수 없음.
		 * */
		ReissueDto dto = new ReissueDto();
		dto.setId(request.getHeader("REISSUE-ID"));
		dto.setIp(request.getHeader("REISSUE-IP"));
		dto.setAgent(request.getHeader("REISSUE-AGENT"));
		dto.setDevice(request.getHeader("REISSUE-DEVICE"));
		
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(reissueAuthToken(dto));
		response.getWriter().flush();
		
	};
	
	/** 발급 중 오류가 발생한다면 INVALID를 검증서버에 반환함으로써 예외처리 */
	private String reissueAuthToken(ReissueDto dto) {
		try {
			
			String token = TokenUtil.reissueJWE(dto,
					JWT_ENCRYPT_SIGN, JWT_ENCRYPT_TOKEN,
					JWT_ISSUER, JWT_AUDIENCE, JWT_EXPIRED);
			
			/** 로그인 결과 저장 - 갱신( 사용자의 마지막 접속일을 갱신함 ) */
			authDao.regLoginResult(new ResultDto("reissue", authUtil.encryptName(dto.getId()), dto.getIp()));
			/** 사용자의 마지막 접속일을 갱신 */
//			authDao.uptLoginDate(id);
			
			return token;
			
		} catch(JOSEException e) {
			return "INVALID";
		}
	};
	
	/** 리소스 경로가 아니거나, /refresh 경로 + 특정조건 맞지 않는 경우 */
	private void redirect(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		/** 쿠키에서 토큰을 가져와서 */
		Cookie[] cookies = request.getCookies();
		String token = null;
		if(cookies != null)
			token = CookieUtil.extractValue(request, cookies, JWT_NAME);
		
		/** 토큰이 존재하고, 검증서버에 검증요청의 반환이 유효하다면 이전페이지 or 메인페이지로 이동 */
		if(token != null && validateToken(request, token)) {
			
			String referer = request.getHeader("Referer");
			
			/** Redirect 경로 검증 */
			if(RedirectUtil.validateReferer(referer)) { response.sendRedirect(referer); }
			else { response.sendRedirect(HOME_SERVER); }
			return;
			
		}
		
		/** 이외의 경우인데 만약 토큰이 존재한다면 토큰이 탈취됐다고 판단함 = 파기처리 */
		else {
			
			if(token != null) {
				clearAuth(response, token, cookies);
				clearSession(request);
			}
			
		}
		
		chain.doFilter(request, response);
		
	};
	
	/** 검증서버에 토근 검증요청 로직 */
	private boolean validateToken(HttpServletRequest request, String token) {
		
		RestTemplate template = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set(JWT_HEADER, JWT_KEY + token);
		headers.set(USER_AGENT, request.getHeader(USER_AGENT));
//		headers.set("isXHR", isXHRRequest(request)? "true":"false");
		
		HttpEntity<String> entity = new HttpEntity<>("", headers);
		
		/** try부분은 response의 상태코드가 200이어야만 동작함. */
		try {
			ResponseEntity<String> response = template.exchange(AUTH_SERVER, HttpMethod.GET, entity, String.class);
			return response.getStatusCode() == HttpStatus.OK;
		}
		/** 검증실패 */
		catch(HttpClientErrorException e) { return false; }
		/** 검증서버 연결실패 */
		catch(RestClientException e) { return false; }
		
	};
	
	/** 쿠키 제거 + Redis 제거 + Remember Me 제거 */
	private void clearAuth(HttpServletResponse response, String token, Cookie[] cookies) {
		
		/** 쿠키 제거 */
		CookieUtil.clearCookie(response, cookies, JWT_NAME, JWT_DOMAIN, JWT_PATH);
		
		/** Redis 제거 + Remember Me 제거 */
		clearRedisAndRefreshToken(response, token, cookies);
		
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
	
//	/**
//	 * 요청유형 구분
//	 * (1) 사용자가 Ajax나 Axios등을 활용해서 Request가 발생하는 경우
//	 * (2) 사용자가 인터넷 주소창을 활용해서 Request가 발생하는 경우
//	 * 
//	 * = 아래의 조건이 모두 충족하면 XHR 요청으로 판단함.
//	 * */
//	private boolean isXHRRequest(HttpServletRequest request) {
//		String xhr = request.getHeader(XHR_HEADER);
//		String accept = request.getHeader(ACCEPT_HEADER);
//		return ((xhr != null && XHR_HEADER_VALUE.equals(xhr))
//				&& (accept != null && accept.contains(MediaType.APPLICATION_JSON_VALUE)));
//	}
	
}