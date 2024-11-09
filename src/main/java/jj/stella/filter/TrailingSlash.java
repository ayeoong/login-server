package jj.stella.filter;

import java.io.IOException;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TrailingSlash extends OncePerRequestFilter {
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
		
		String uri = request.getRequestURI();
		String url = ServletUriComponentsBuilder.fromRequest(request).build().toString();
		if(url.endsWith("/") && !uri.equals("/")) {
			
			url = url.substring(0, url.length() - 1);
			
			response.setHeader(HttpHeaders.LOCATION, url);
			response.setStatus(HttpStatus.MOVED_PERMANENTLY.value());
			
		} else if(uri.equals("")) {
			response.setHeader(HttpHeaders.LOCATION, url + "/");
			response.setStatus(HttpStatus.MOVED_PERMANENTLY.value());
		} else chain.doFilter(request, response);
		
	};
	
}