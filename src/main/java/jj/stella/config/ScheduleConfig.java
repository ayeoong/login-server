package jj.stella.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Component
public class ScheduleConfig {

	@Value("${server.production.mode}")
	private boolean isProduction;
	
	@Autowired
	private RedisTemplate<String, Object> redisTemplate;
	
	/** 오전 6시, 오후 18시 */
	@Scheduled(cron = "0 0 6,18 * * *")
	/** 3시간 내로 중복실행 방지 */
	@SchedulerLock(name="redisLogLock", lockAtLeastFor="PT3H", lockAtMostFor="PT3H")
//	@Scheduled(cron = "*/5 * * * * *")
	public void redisLogData() throws Exception {
		if(isProduction) {
			
			System.out.println("======= Scheduled Action =======");
			
			List<Map<String, Object>> dataArr = new ArrayList<Map<String, Object>>();
			Set<String> logKeys = redisTemplate.keys("logs::*");
			Iterator<String> it = logKeys.iterator();
			while(it.hasNext()) {
				
				String next = it.next();
				Map<String, Object> data = new HashMap<>();
				Map<Object, Object> hash = redisTemplate.opsForHash().entries(next);
				for(Map.Entry<Object, Object> entry:hash.entrySet()) {
					data.put(String.valueOf(entry.getKey()), entry.getValue());
				};
				
				dataArr.add(data);
				
			};
			
//			int cnt = authDao.regRedisLog(dataArr);
			int cnt = 1;
			if(cnt >= 1 && !logKeys.isEmpty()) {
				redisTemplate.delete(logKeys);
				System.out.println("======= " + logKeys.size() + " log(s) deleted from Redis. =======");
			};
			
		}
	};
	
}