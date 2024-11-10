package jj.stella.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.redis.spring.RedisLockProvider;

/**
 * 외장 Tomcat으로 구동시킨 경우 중복해서 배포되는 현상이 발생함
 * ScheduleConfig에 걸린 스케줄에 따라 동작시키는 로직도 중복해서 실행됨
 * 
 * 이에 대한 조치로 특정시간동안 중복해서 동작하지 않도록 함.
 * ( ScheduleConfig에 설정됭 @SchedulerLock을 확인할 것 )
 */
@Configuration
public class ScheduleLockConfig {
	
	@Bean
	public LockProvider lockProvider(RedisConnectionFactory connectionFactory) {
		return new RedisLockProvider(connectionFactory);
	};
	
}