package jj.stella.filter.auth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jj.stella.entity.dto.UserDto;
import jj.stella.entity.vo.UserVo;
import jj.stella.repository.dao.CommonDao;
import jj.stella.repository.service.RedisService;
import jj.stella.util.RedisLog;
import jj.stella.util.SHA256;

public class AuthFailure implements AuthenticationFailureHandler {
	
	private CommonDao commonDao;
	private RedisService redisService;
	public AuthFailure(CommonDao commonDao, RedisService redisService) {
		this.commonDao = commonDao;
		this.redisService = redisService;
	}
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		
//		String id = request.getParameter("username");
//		
//		/** Redis 로그를 위한 조회 */
//		UserVo user = getUser(encryptName(id));
//		if(user != null) {
//			
//			/** 로그인 실패 로그 */
//			try {
//				redisService.setLog(RedisLog.loginFailure(user.getIdx(), id));
//			}
//			
//			/** Redis PrintStackTrace */
//			catch(Exception e) { e.printStackTrace(); }
//			
//		}
		
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		
		Map<String, Object> map = new HashMap<>();
		map.put("str", exception.getMessage());
		
		ObjectMapper mapper = new ObjectMapper();
		String result = mapper.writeValueAsString(map);
		response.getWriter().write(result);
		response.getWriter().flush();
		
		
	}
	
	/** ID 암호화 */
	private String encryptName(String id) {
		SHA256 sha = new SHA256();
		return sha.getSHA256Type(id);
	}
	
	/** 유저 존재 여부 */
	private UserVo getUser(String username) {
		
		UserDto dto = new UserDto();
		dto.setUsername(username);
		
		return commonDao.getUser(dto);
		
	}
	
}