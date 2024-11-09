package jj.stella.filter.auth;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthSuccess implements AuthenticationSuccessHandler {

	private String LOGIN_SERVER;
	public AuthSuccess(String LOGIN_SERVER) {
		this.LOGIN_SERVER = LOGIN_SERVER;
	};
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		response.sendRedirect(LOGIN_SERVER);
	};
	
}