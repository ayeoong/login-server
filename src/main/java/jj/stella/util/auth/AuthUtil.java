package jj.stella.util.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.UserDto;
import jj.stella.entity.vo.UserVo;
import jj.stella.filter.auth.AuthDetails;
import jj.stella.repository.dao.AuthDao;
import jj.stella.util.SHA256;

@Component
public class AuthUtil {
	
	@Autowired
	private AuthDao authDao;
	@Autowired
	private PasswordEncoder encoder;
	
	/** ID 암호화 */
	public String encryptName(String username) {
		SHA256 sha = new SHA256();
		return sha.getSHA256Type(username);
	};
	
	/** 유저 존재 여부 */
	public UserVo getUser(String id) {
		
		UserDto dto = new UserDto();
		dto.setUsername(id);
		
		return authDao.getUser(dto);
		
	};
	
	/** 사용자 검증( ID + Password / 토큰검증 아님 ) */
	public UserVo validateUser(String id, String password, Object object) {
		
		String username = encryptName(id);
		UserVo user = getUser(username);
		
		/** ID 확인 */
		if(user == null)
			throw new UsernameNotFoundException("존재하지 않는 사용자입니다.");
		
		/** Password 확인 */
		if(!encoder.matches(password, user.getPassword()))
			throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
		
		/** Remember Me - Refresh Token 제거 */
		clearRefreshToken(id, (AuthDetails) object);
		
		return user;
		
	};
	
	/** Remember Me - Refresh Token 제거 */
	private void clearRefreshToken(String id, AuthDetails details) {
		
		RefreshTokenDto dto = new RefreshTokenDto();
		dto.setId(id);
		dto.setDevice(details.getDevice());
		if(authDao.getRefreshToken(dto) >= 1)
			authDao.delRefreshToken(dto);
		
	};
}