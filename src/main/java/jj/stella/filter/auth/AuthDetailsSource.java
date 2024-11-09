package jj.stella.filter.auth;

import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import jakarta.servlet.http.HttpServletRequest;

/**
 * JWT만들 때 사용자 디바이스 고유번호( JTI를 설정 ), IP를 설정하기 위한 용도
 * - 구체적으로 IP나 User-Agent를 가져올 수 있는 HttpServletRequest에 접근할 수 없어서
 *   AuthDetailsSource, AuthDetails를 사용함
 * 
 * - HttpServletRequest로 가져올 수 있는 IP는 공인 IP가 아니기 때문에
 *   공인 IP를 가져오는 로직이 필요함
 */
public class AuthDetailsSource extends WebAuthenticationDetailsSource {

	private String ORIGIN_IP_API;
	public AuthDetailsSource(String ORIGIN_IP_API) {
		this.ORIGIN_IP_API = ORIGIN_IP_API;
	};
	
	@Override
	public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
		return new AuthDetails(request, ORIGIN_IP_API);
	};
	
}