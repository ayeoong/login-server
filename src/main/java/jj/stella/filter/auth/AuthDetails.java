package jj.stella.filter.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 실제 인증이 진행되는 AuthProvider에서 HttpServletRequest를 사용할 수 없기 때문에 AuthDetails로 구현
 * + IP호출 로직을 구현
 */ 
public class AuthDetails extends WebAuthenticationDetails {
	
	private static final long serialVersionUID = 1L;
	
	/** 사용자의 IP 주소 */
	private final String ip;
	/** 사용자의 에이전트 */
	private final String agent;
	/** 사용자의 기기 식별번호 */
	private final String device;
	/** 사용자의 Remember Me 유무 */
	private final boolean rememberMe;
	/** 연결 및 읽기 타임아웃 시간( ms ) */
	private static final int TIMEOUT = 2000;
	/** 클라이언트 실제 IP 주소를 찾기 위한 헤더 목록 */
	private static final List<String> HEADERS = Arrays.asList(
		"X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_X_FORWARDED_FOR",
		"HTTP_X_FORWARDED", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_CLIENT_IP", "HTTP_VIA"
	);
	
	public AuthDetails(HttpServletRequest request, String ORIGIN_IP_API) {
		
		super(request);
		/** IP 주소 찾기 시도 후, 없으면 요청으로부터 직접 가져옴 */
		this.ip = findIp(request, ORIGIN_IP_API)
			.orElse(request.getRemoteAddr());
		/** 사용자의 에이전트 정보 */
		this.agent = request.getHeader("User-Agent");
		/** 사용자의 기기 식별번호 */
		this.device = request.getParameter("device");
		/** 사용자의 Remember Me 유무 */
		this.rememberMe = "true".equals(request.getParameter("rememberMe"));
		
	};
	
	public String getIp() {
		return ip;
	};
	public String getAgent() {
		return agent;
	};
	public String getDevice() {
		return device;
	};
	public boolean isRememberMe() {
		return rememberMe;
	};
	
	/**
	 * 요청으로부터 클라이언트의 IP 주소를 찾는다.
	 * @param request 클라이언트의 HTTP 요청
	 * @return 클라이언트의 IP 주소를 포함하는 Optional 객체
	 */
	private Optional<String> findIp(HttpServletRequest request, String api) {
		return HEADERS.stream()
				/**
				 * 각 헤더에 대한 요청 값을 매핑
				 * request::getHeader === request.getHeader(name)
				 * 여기서 name은 stream의 각 요소
				 */
				.map(request::getHeader)
				/** 유효한 IP 주소만 필터링 */
				.filter(this::isValid)
				/** 첫 번째 유효한 IP 주소 찾기 */
				.findFirst()
				/** IP 주소가 여러 개일 경우 첫 번째만 사용 */
				.map(ip -> ip.split(",")[0].trim())
				/**
				 * 외부 서비스를 통해 IP를 가져오는 백업 방식
				 * 위 절차의 최종값이 Null이라면 외부 서비스로 Ip를 호출 후 검증.
				 */
				.or(() -> Optional.ofNullable(fetchIp(api)).filter(this::isValid));
	};
	
	/**
	 * IP 주소가 유효한지 검증.
	 * @param ip 검증할 IP 주소
	 * @return 유효성 검사 결과
	 */
	private boolean isValid(String ip) {
		return ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip);
	};
	
	/**
	 * 외부 서비스를 통해 공인 IP 주소를 호출.
	 * @return 공인 IP 주소 또는 에러 메시지
	 */
	private String fetchIp(String api) {
		
		try {
			
			HttpURLConnection connection = (HttpURLConnection) new URL(api).openConnection();
			connection.setRequestMethod("GET");
			// n초 내에 연결되어야 함
			connection.setConnectTimeout(TIMEOUT);
			// n초 내에 데이터를 읽어야 함
			connection.setReadTimeout(TIMEOUT);
			
			int resCode = connection.getResponseCode();
			if(resCode == HttpURLConnection.HTTP_OK) {
				try(BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
					return reader.readLine();
				}
			} else
				System.out.println("공인 IP주소 호출 GET요청 실패 / Response Code: " + resCode);
			
		} catch(IOException e) {
			System.err.println("Error fetching IP: " + e.getMessage());
		}
		
		return null;
		
	};
	
}