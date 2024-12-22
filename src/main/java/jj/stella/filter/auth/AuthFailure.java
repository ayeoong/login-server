package jj.stella.filter.auth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jj.stella.entity.dto.ResultDto;
import jj.stella.entity.vo.UserVo;
import jj.stella.repository.dao.AuthDao;
import jj.stella.util.auth.AuthUtil;

public class AuthFailure implements AuthenticationFailureHandler {
	
	private AuthDao authDao;
	private AuthUtil authUtil;
	public AuthFailure(AuthDao authDao, AuthUtil authUtil) {
		this.authDao = authDao;
		this.authUtil = authUtil;
	}
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

		String username = request.getParameter("username");
		WebAuthenticationDetails details = (WebAuthenticationDetails) request.getSession(false)
				.getAttribute("St2lla-Authenticaion-Details");
		
		String id = authUtil.encryptName(username);
		String ip = ((AuthDetails) details).getIp();
		UserVo user = authUtil.getUser(id);
		
		/** 로그인 결과 저장 - 실패 */
		if(user != null)
			authDao.regLoginResult(new ResultDto("failure", id, ip));
		
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		
		Map<String, Object> map = new HashMap<>();
		map.put("str", exception.getMessage());
		
		ObjectMapper mapper = new ObjectMapper();
		String result = mapper.writeValueAsString(map);
		response.getWriter().write(result);
		response.getWriter().flush();
		
	};
	
}