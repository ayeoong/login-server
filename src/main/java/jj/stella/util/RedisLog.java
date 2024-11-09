package jj.stella.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import jj.stella.entity.dto.RedisDto;
import jj.stella.filter.auth.AuthDetails;

public class RedisLog {
	
	/** 로그인 시도 */
	public static RedisDto loginTrial(int ino, String usr, AuthDetails details) {
		return createDto(
			ino, "login", "'" + usr + "'계정 로그인을 시도했습니다."
					+ " [ Ip = " + details.getIp() + ","
					+ " Device = " + details.getDevice() + ","
					+ " Agent = " + details.getAgent() + " ]"
		);
	};
	
	/** 로그인 성공 */
	public static RedisDto loginSuccess(int ino, String usr, AuthDetails details) {
		return createDto(
			ino, "login success", "'" + usr + "'계정 로그인에 성공했습니다."
					+ " [ Ip = " + details.getIp() + ","
					+ " Device = " + details.getDevice() + ","
					+ " Agent = " + details.getAgent() + " ]"
		);
	};
	
	/** 로그인 실패 */
	public static RedisDto loginFailure(int ino, String usr) {
		return createDto(
			ino, "login fail", "'" + usr + "'계정 로그인에 실패했습니다."
		);
	};
	
	private static RedisDto createDto(int ino, String section, String conts) {
		
		RedisDto dto = new RedisDto();
		LocalDateTime now = LocalDateTime.now();
		
		dto.setIno(ino);
		dto.setSection(section);
		dto.setConts(conts);
		dto.setDate(now.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
		
		return dto;
		
	}
	
}