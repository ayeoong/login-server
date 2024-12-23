package jj.stella.util.cookie;

import java.util.Arrays;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CookieUtil {
	
	/**
	 * 이 메서드는 HTTP 응답에 쿠키를 설정합니다.
	 * 쿠키 이름, 쿠키 값, 도메인, 경로, 만료일(초), HttpServletResponse
	 *
	 * @param key 쿠키 이름
	 * @param value 쿠키 값
	 * @param domain 쿠키가 유효한 도메인
	 * @param path 쿠키가 유효한 경로
	 * @param expireTime 쿠키 만료 시간( 초 단위 )
	 * @param response HttpServletResponse 객체, 쿠키를 추가할 HTTP 응답
	 */
	public static void setCookie(String key, String value, String domain, String path,
		long expireTime, HttpServletResponse response) {
		
		Cookie cookie = new Cookie(key, value);
		 
		cookie.setDomain(domain);
		cookie.setPath(path);
		cookie.setMaxAge((int) expireTime);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		
		response.addCookie(cookie);
		
	};
	
	
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

	/** 쿠키 제거 */
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