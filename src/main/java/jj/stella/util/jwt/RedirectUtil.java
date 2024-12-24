package jj.stella.util.jwt;

import java.util.List;

import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;

public class RedirectUtil {
	
	private final static AntPathMatcher pathMatcher = new AntPathMatcher();
	private static final List<String> SKIP_PATHS = List.of("/resources/**", "/favicon.ico");
	private static final List<String> REQUIRED_REISSUE_HEADERS = List.of("REISSUE-ID", "REISSUE-IP", "REISSUE-AGENT", "REISSUE-DEVICE");
	private static final List<String> ALLOWED_REFERERS = List.of(
		"http://localhost", "https://st2lla.co.kr", "https://dev.st2lla.co.kr"
	);
	
	/**
	 * 주어진 경로가 스킵할 경로 리스트에 포함되는지 검사하는 메서드
	 * @param path    검사할 경로
	 * 
	 * @return boolean 경로가 스킵 리스트에 포함되면 true, 그렇지 않으면 false
	 * */
	public static boolean validateSkipPath(String path) {
		return SKIP_PATHS.stream().anyMatch(skipPath -> pathMatcher.match(skipPath, path));
	};
	
	/**
	 * 주어진 경로가 "/refresh"인지 확인하고, 필요한 모든 HTTP 헤더가 있는지 검사하는 메서드
	 * @param request   HttpServletRequest 객체, 요청에 포함된 헤더 정보를 확인하기 위해 사용
	 * @param path      검사할 경로
	 * 
	 * @return boolean 주어진 경로가 "/refresh"이고 모든 필수 헤더가 존재하면 true, 그렇지 않으면 false
	 * */
	public static boolean validateRefreshPath(HttpServletRequest request, String path) {
		return pathMatcher.match("/refresh", path) &&
			REQUIRED_REISSUE_HEADERS.stream().allMatch(header -> request.getHeader(header) != null);
	};
	
	/**
	 * Referer 헤더를 검증하는 메서드
	 * @param path      검증할 referer 문자열
	 * 
	 * @return boolean  referer가 유효한 시작 부분을 가지면 true, 그렇지 않거나 특정 포트를 사용하면 false
	 * */
	public static boolean validateReferer(String path) {
		if(path == null || path.startsWith("http://localhost:8080"))
			return false;
		return ALLOWED_REFERERS.stream().anyMatch(path::startsWith);
	};
	
}