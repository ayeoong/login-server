package jj.stella.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Configuration
// server.* 매핑
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
	
	// auth.jwt.* 매핑
	private Jwt jwt;
	
	@Getter
	@Setter
	public static class Jwt {
		
		private String header;		// auth.jwt.header
		private String key;			// auth.jwt.key
		private String name;		// auth.jwt.name
		private String issuer;		// auth.jwt.issuer
		private String audience;	// auth.jwt.audience
		private String domain;		// auth.jwt.domain
		private String path;		// auth.jwt.path
		private String expired;		// auth.jwt.expired
		
		// auth.jwt.refresh.* 매핑
		private Refresh refresh;
		
		@Getter
		@Setter
		public static class Refresh {
			
			private String issuer;		// auth.jwt.refresh.issuer
			private String audience;	// auth.jwt.refresh.audience
			
		};
		
		// auth.jwt.encrypt.* 매핑
		private Encrypt encrypt;
		
		@Getter
		@Setter
		public static class Encrypt {
			
			private String sign;	// auth.jwt.encrypt.sign
			private String token;	// auth.jwt.encrypt.token
			
			// auth.jwt.encrypt.refresh.* 매핑
			private Refresh refresh;
			
			@Getter
			@Setter
			public static class Refresh {
				
				private String sign;	// auth.jwt.encrypt.refresh.sign
				private String token;	// auth.jwt.encrypt.refresh.token
				
			};
			
		};
		
	};
	
	// auth.csrf.* 매핑
	private Csrf csrf;
	
	@Getter
	@Setter
	public static class Csrf {
		
		private String name;		// auth.csrf.name
		private String parameter;	// auth.csrf.parameter
		private String header;		// auth.csrf.header
		
	};
	
}