package jj.stella.util.jwt;

import java.util.List;

public class RedirectUtil {
	private static final List<String> ALLOWED_REFERERS = List.of(
		"http://localhost",
		"http://dev.captivision.co.kr",
		"https://login.dev.captivision.co.kr",
		"http://intra.captivision.co.kr",
		"https://intra.captivision.co.kr"
	);
	
	public static boolean validateReferer(String url) {
		if(url == null)
			return false;
		if(url.startsWith("http://localhost:8080"))
			return false;
		return ALLOWED_REFERERS.stream().anyMatch(url::startsWith);
	};
	
}