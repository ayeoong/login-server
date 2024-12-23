package jj.stella.util.redis;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;

public class RedisUtil {
	
	/**
	 * 데이터 저장( 시간 제한 없음 )
	 * @param key   Redis 키
	 * @param value 저장할 값
	*/
	public static void save(RedisTemplate<String, Object> template, String key, Object value) {
		template.opsForValue().set(key, value);
	};
	
	/**
	 * 데이터 저장( 시간 제한 있음 )
	 * @param key      Redis 키
	 * @param value    저장할 값
	 * @param timeout  만료 시간( 초 단위 )
	*/
	public static void save(RedisTemplate<String, Object> template, String key, Object value, long timeout) {
		template.opsForValue().set(key, value, timeout, TimeUnit.SECONDS);
	};
	
	/**
	 * 데이터 저장( 시간 제한 있음 )
	 * @param key      Redis 키
	 * @param value    저장할 값
	 * @param timeout  만료 시간
	 * @param unit     만료 시간 단위
	*/
	public static void save(RedisTemplate<String, Object> template, String key, Object value, long timeout, TimeUnit unit) {
		template.opsForValue().set(key, value, timeout, unit);
	};

	/**
	 * 데이터 삭제
	 * @param key 삭제할 Redis 키
	*/
	public static void revoke(RedisTemplate<String, Object> template, String key) {
		template.delete(key);
	};
	
}