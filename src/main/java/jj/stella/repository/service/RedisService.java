package jj.stella.repository.service;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import jj.stella.entity.dto.RedisDto;

@Service
public class RedisService {
	
	private final RedisTemplate<String, Object> redisTemplate;
	
	public RedisService(RedisTemplate<String, Object> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}
	
	public void setLog(RedisDto dto) throws Exception {
		
		/** 고유 Log Key 생성 >>> "logs::" 접두사 + 고유 Key 접미사 = 고유한 Log Key */
		String key = "logs::" + UUID.randomUUID();
		HashOperations<String, Object, Object> ops = redisTemplate.opsForHash();
		
		/** Dto를 Map으로 변환 */
		Map<String, Object> map = convertData(dto);
		
		/**
		 * 순서 중요함.
		 * expire가 먼저오면 TTL 설정이 안됨.
		 */
		ops.putAll(key, map);
		redisTemplate.expire(key, 12, TimeUnit.HOURS);
		
	}
	
	private Map<String, Object> convertData(RedisDto dto) {
		
		Map<String, Object> result = new HashMap<>();
		/** dto의 모든 필드를 반복하면서 각 필드의 이름과 값을 Map에 저장. */
		Field[] fields = dto.getClass().getDeclaredFields();
		for(Field field:fields) {
			
			field.setAccessible(true);
			
			/** 필드의 이름을 키로, 필드의 값을 값으로 하여 Map에 추가 */
			try {
				result.put(field.getName(), field.get(dto));
			}
			
			catch (IllegalAccessException e) {
				/** 예외 처리 로직 */
				throw new RuntimeException("Failed to access field value", e);
			}
			
		}
		
		return result;
		
	}
	
}