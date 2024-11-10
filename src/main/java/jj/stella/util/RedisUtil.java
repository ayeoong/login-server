package jj.stella.util;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

@Component
public class RedisUtil {
	
	@Autowired
	private RedisTemplate<String, Object> redisTemplate;
	
	/**
	 * 키 존재 여부 확인
	 * @param key 확인할 Redis 키
	 * @return 키 존재 여부
	*/
	public boolean has(String key) {
		return Boolean.TRUE.equals(redisTemplate.hasKey(key));
	};
	
	/**
	 * 데이터 가져오기
	 * @param key Redis 키
	 * @return 저장된 값
	*/
	public Object get(String key) {
		return redisTemplate.opsForValue().get(key);
	};
	
	/**
	 * 데이터 저장 (시간 제한 없음)
	 * @param key   Redis 키
	 * @param value 저장할 값
	*/
	public void save(String key, Object value) {
		redisTemplate.opsForValue().set(key, value);
	};
	
	/**
	 * 데이터 저장 (시간 제한 있음)
	 * @param key      Redis 키
	 * @param value    저장할 값
	 * @param timeout  만료 시간 (초 단위)
	*/
	public void save(String key, Object value, long timeout) {
		redisTemplate.opsForValue().set(key, value, timeout, TimeUnit.SECONDS);
	};
	
	/**
	 * 데이터 삭제
	 * @param key 삭제할 Redis 키
	*/
	public void revoke(String key) {
		redisTemplate.delete(key);
	};
	
	/**
	 * 패턴에 맞는 키 찾기
	 * @param pattern 키 패턴
	 * @return 해당 패턴을 만족하는 키 집합
	*/
	public Set<String> patternKeys(String pattern) {
		return redisTemplate.keys(pattern);
	};

	/**
	 * 키의 만료 시간 조회
	 * @param key 조회할 키
	 * @param unit 시간 단위
	 * @return 만료 시간 (지정된 시간 단위)
	*/
	public long getExpire(String key, TimeUnit unit) {
		return redisTemplate.getExpire(key, unit);
	};
	
}