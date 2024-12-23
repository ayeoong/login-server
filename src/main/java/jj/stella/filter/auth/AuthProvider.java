package jj.stella.filter.auth;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import jj.stella.entity.vo.UserVo;
import jj.stella.util.auth.AuthUtil;

@Component
public class AuthProvider implements AuthenticationProvider {
	
	@Autowired
	private AuthUtil authUtil;
	
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
		UserVo user = authUtil.validateUser(username, password, auth.getDetails());
		if(!user.isEnable())
			throw new DisabledException("귀하의 계정은 현재 비활성화 상태입니다.");
		
		List<GrantedAuthority> authorityRoles = new ArrayList<GrantedAuthority>();
//		User principal = new User(username, password, authorityRoles);
		
		/** 사용자의 마지막 접속일을 갱신 */
//		return new UsernamePasswordAuthenticationToken(principal, password, authorityRoles);
		return new UsernamePasswordAuthenticationToken(username, password, authorityRoles);
		
	};
	
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	};
	
}