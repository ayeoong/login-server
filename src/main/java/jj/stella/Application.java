package jj.stella;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableScheduling;

import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;

@EnableCaching		// Cache 사용하겠다 선언
@EnableScheduling	// Cache에 들어있는 로그 스케줄로 한꺼번에 Insert
@EnableSchedulerLock(defaultLockAtMostFor="PT3H")	// 3시간동안 중복 스케줄 동작 방지
@SpringBootApplication
public class Application extends SpringBootServletInitializer {
	
	public static void main(String[] args) throws Exception {
		
		/** 만약 AWS Secrets Manager를 사용한다면 아래 주석 풀어서 사용 */
//		Region region = Region.AP_NORTHEAST_2;
//		String secret = System.getenv("PROPS_INTRA");
//		ProfileCredentialsProvider provider = ProfileCredentialsProvider.builder()
//			.profileName("default")
//			.build();
//		
//		SecretsManagerClient client = SecretsManagerClient.builder()
//				.region(region)
//				.credentialsProvider(provider)
//				.build();
//		
//		GetSecretValueRequest req = GetSecretValueRequest.builder()
//			.secretId(secret)
//			.build();
//		
//		String value = client.getSecretValue(req).secretString();
//		// GetSecretValueResponse getSecretValueResponse = client.getSecretValue(request);
//		
//		ObjectMapper object = new ObjectMapper();
//		TypeReference<Map<String, String>> type = new TypeReference<Map<String, String>>() {};
//		Map<String, String> secrets = object.readValue(value, type);
//		for(Map.Entry<String, String> entry:secrets.entrySet())
//			System.setProperty(entry.getKey(), entry.getValue());
//		
//		// 환경변수 확인하려면 주석 풀기
//		// secrets.forEach((key, val) -> System.out.println("Loaded secret: " + key + " = " + val));
		
		System.setProperty("server.servlet.context-path", "/");
		SpringApplication.run(Application.class, args);
		
	}
	
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(Application.class);
	}
	
}
