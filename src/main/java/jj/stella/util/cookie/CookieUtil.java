package jj.stella.util.cookie;

import java.util.Arrays;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CookieUtil {
	
	/**
	 * 쿠키를 설정하는 메서드
	 * HttpServletResponse, 쿠키 이름, 쿠키 값, 도메인, 경로, 만료일(초) 
	 *
	 * @param response HttpServletResponse 객체, 쿠키를 추가할 HTTP 응답
	 * @param key 쿠키 이름
	 * @param value 쿠키 값
	 * @param domain 쿠키가 유효한 도메인
	 * @param path 쿠키가 유효한 경로
	 * @param expireTime 쿠키 만료 시간( 초 단위 )
	 */
	public static void setCookie(HttpServletResponse response, String key, String value, String domain, String path,
		long expireTime) {
		
		Cookie cookie = new Cookie(key, value);
		 
		cookie.setDomain(domain);
		cookie.setPath(path);
		cookie.setMaxAge((int) expireTime);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		
		response.addCookie(cookie);
		
	};
	
	/**
	 * 특정 이름을 가진 쿠키의 값을 추출하는 메서드
	 * 
	 * @param request       HTTP 요청 객체, 쿠키를 포함하고 있습니다.
	 * @param cookies       쿠키 배열
	 * @param cookieName    추출하려는 쿠키의 이름
	 * @return 해당 쿠키의 값 또는 null( 쿠키가 없거나 이름이 일치하지 않을 경우 )
	 */
	public static String extractValue(HttpServletRequest request, Cookie[] cookies, String cookieName) {
		
//		String token = request.getHeader(JWT_HEADER);
//		if(token != null && token.startsWith(JWT_KEY))
//			return token.substring(JWT_KEY.length());
		if(cookies != null) {
			return Arrays.stream(request.getCookies())
					.filter(cookie -> cookieName.equals(cookie.getName()))
					.findFirst()
					.map(Cookie::getValue)
					.orElse(null);
		}
		
		return null;
		
	};

	/**
	 * 특정 이름을 가진 쿠키를 제거하는 메서드
	 * 
	 * @param response        HTTP 응답 객체
	 * @param cookies         쿠키 배열
	 * @param cookieName      삭제하려는 쿠키의 이름
	 * @param cookieDomain    설정할 쿠키의 도메인
	 * @param cookiePath      설정할 쿠키의 경로
	 */
	public static void clearCookie(HttpServletResponse response, Cookie[] cookies,
		String cookieName, String cookieDomain, String cookiePath) {
		Arrays.stream(cookies)
			.filter(cookie -> cookieName.equals(cookie.getName()))
			.forEach(cookie -> {
				
				cookie.setDomain(cookieDomain);
				cookie.setPath(cookiePath);
				cookie.setValue("");
				cookie.setMaxAge(0);
				
				response.addCookie(cookie);
				
			});
	};
	
}