package jj.stella.filter.auth;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.UserDto;
import jj.stella.entity.vo.UserVo;
import jj.stella.repository.dao.CommonDao;
import jj.stella.repository.service.RedisService;
import jj.stella.util.RedisLog;
import jj.stella.util.SHA256;

@Component
public class AuthProvider implements AuthenticationProvider {
	
	// 비밀번호 암호화 ( 단방향 복호화 불가능 )
	@Autowired
	private PasswordEncoder encoder;
	
	@Autowired
	private CommonDao commonDao;
	
	@Autowired
	private RedisService redisService;
	
	// AuthenticationException 종류
	// UsernameNotFoundException: 계정 없음
	// BadCredentialsException: 비밀번호 불일치
	// AccountExpiredException: 계정 만료
	// CredentialExpiredException: 비밀번호 만료
	// DisabledException: 계정 비활성화
	// LockedException: 계정잠금
	@Override
	public Authentication authenticate(Authentication auth) throws AuthenticationException {
		
		String username = auth.getName();
		String password = auth.getCredentials().toString();
		UserVo user = validateUser(username, password, auth.getDetails());
		if(!user.isEnable())
			throw new DisabledException("귀하의 계정은 현재 비활성화 상태입니다.");
		
		List<GrantedAuthority> authorityRoles = new ArrayList<GrantedAuthority>();
//		User principal = new User(username, password, authorityRoles);
		
		/** 사용자의 마지막 접속일을 갱신 */
		// updateLastLoginDate(username);
		
//		return new UsernamePasswordAuthenticationToken(principal, password, authorityRoles);
		return new UsernamePasswordAuthenticationToken(username, password, authorityRoles);
		
	};
	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	};
	
	/** 사용자 인증 로직 */
	private UserVo validateUser(String id, String password, Object object) {
		
		String username = encryptName(id);
		UserVo user = getUser(username);
		
		/** ID 확인 */
		if(user == null)
			throw new UsernameNotFoundException("존재하지 않는 사용자입니다.");
		
		/** 로그인 시도 로그 */
//		try {
//			redisService.setLog(RedisLog.loginTrial(user.getIdx(), id, (AuthDetails) object));
//		}
		
		/** Redis PrintStackTrace */
//		catch(Exception e) { e.printStackTrace(); }
		
		/** Password 확인 */
		if(!encoder.matches(password, user.getPassword()))
			throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
		
		/** Remember Me - Refresh Token 제거 */
		clearRefreshToken(id, (AuthDetails) object);
		
		return user;
		
	};
	
	/** ID 암호화 */
	private String encryptName(String id) {
		SHA256 sha = new SHA256();
		return sha.getSHA256Type(id);
	};
	
	/** 유저 존재 여부 */
	private UserVo getUser(String username) {
		
		UserDto dto = new UserDto();
		dto.setUsername(username);
		
		return commonDao.getUser(dto);
		
	};
	
	/** Remember Me - Refresh Token 제거 */
	private void clearRefreshToken(String id, AuthDetails details) {
		
		RefreshTokenDto dto = new RefreshTokenDto();
		dto.setId(id);
		dto.setDevice(details.getDevice());
		if(commonDao.getRefreshToken(dto) >= 1)
			commonDao.removeRefreshToken(dto);
		
	};
	
	/** 사용자의 마지막 접속일을 갱신 */
	private void updateLastLoginDate(String id) {
		commonDao.updateLastLoginDate(id);
	};
	
}