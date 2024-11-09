package jj.stella.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
@EnableRedisRepositories
public class RedisConfig {

	@Autowired
	private Environment env;
	
	@Bean(name="redis")
	public RedisConnectionFactory redis() {
		
		RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
		config.setHostName(env.getProperty("spring.data.redis.host"));
		config.setPort(Integer.parseInt(env.getProperty("spring.data.redis.port")));
		config.setPassword(env.getProperty("spring.data.redis.password"));
		
		return new LettuceConnectionFactory(config);
		
	};
	
	@Bean
	public RedisTemplate<String, Object> redisTemplate() {
		
		RedisTemplate<String, Object> template = new RedisTemplate<>();
		
		template.setConnectionFactory(redis());
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
		
		return template;
		
	};
	
}