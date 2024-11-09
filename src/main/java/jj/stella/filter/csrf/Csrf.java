package jj.stella.filter.csrf;

import java.io.IOException;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class Csrf extends OncePerRequestFilter {
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		
		CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		String header = csrf.getHeaderName();
		String token = csrf.getToken();
		
		// 응답헤더에 XSRF-TOKEN 내려주기 위함.
		if(header == null && token != null)
			response.setHeader(header, token);
		
		chain.doFilter(request, response);
		
	};
	
}