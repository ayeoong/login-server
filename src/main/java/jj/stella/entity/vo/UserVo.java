package jj.stella.entity.vo;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserVo implements UserDetails {
	
	// default
	private static final long serialVersionUID = 1L;
	
	private int ino;
	private String origin;
	private String username;
	private String password;
	private String tempPassword;
	private boolean enable;
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	};
	
	@Override
	public boolean isAccountNonExpired() {
		return false;
	};
	
	@Override
	public boolean isAccountNonLocked() {
		return false;
	};
	
	@Override
	public boolean isCredentialsNonExpired() {
		return false;
	};
	
	@Override
	public boolean isEnabled() {
		return false;
	};
	
}