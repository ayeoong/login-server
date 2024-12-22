package jj.stella.util.cookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

public class CookieUtil {
	public static void setCookie(String key, String value, HttpServletResponse response, long expireTime, String domain, String path) {
		
		Cookie cookie = new Cookie(key, value);
		
		cookie.setDomain(domain);
		cookie.setMaxAge((int) expireTime);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath(path);
		
		response.addCookie(cookie);
		
	}
}