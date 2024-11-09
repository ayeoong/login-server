package jj.stella.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Configuration
// server.url.* 매핑
@ConfigurationProperties(prefix = "server.url")
public class ServerProperties {
	
	private String auth;		// server.url.auth
	private String jti;			// server.url.jti
	private String home;		// server.url.home
	private String login;		// server.url.login
	
	// server.url.api.*매핑
	private Api api;
	
	@Getter
	@Setter
	public static class Api {
		
		private String originIp;	// server.url.auth.origin-ip
		
	};
	
}