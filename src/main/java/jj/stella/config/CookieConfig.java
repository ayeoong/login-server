package jj.stella.config;

import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jj.stella.util.CookieUtil;

/**
 * 쿠키를 설정할 때 도메인을 아래와 같이 설정할 수 있음.
 * (1) [도메인 주소].co.kr
 * (2) .[도메인 주소].co.kr
 * 
 * 1번의 경우는 단일 도메인으로, "[도메인 주소].co.kr/..."처럼 하위 주소에서 모두 호출할 수 있다. 
 * 2번의 경우는 다중 도메인으로, "api.[도메인 주소].co.kr/...", "dev.[도메인 주소].co.kr/..."에서 모두 호출할 수 있다.
 * - [도메인 주소].co.kr으로 설정하게 될 경우 "api.[도메인 주소].co.kr"에서 가져올 수 없음 
 * 
 * java servlet에서는 쿠키의 보안을 위해서, 범용적인 사용을 막기 위해 하위 도메인에서 사용하지 못하도록 차단함
 * 그리고, Spring Boot에서 사용되는 내장형 Tomcat은 도메인에 "."을 시작하는 쿠키 형식(version 0)을 제공하지 않는다.
 * 이를 해결하기 위해 CookieUtil( 커스텀 CookieProcessor ) 생성 후 적용시켜줌
 */
@Configuration
public class CookieConfig {
	
	@Bean
	public WebServerFactoryCustomizer<TomcatServletWebServerFactory> cookieProcessorCustomizer() {
		return factory -> factory.addContextCustomizers(context -> {
			context.setCookieProcessor(new CookieUtil());
		});
	};
	
}