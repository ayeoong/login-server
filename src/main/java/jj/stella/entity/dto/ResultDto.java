package jj.stella.entity.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
/** 모든 필드를 매개변수로 받는 생성자를 자동 생성 */
// @AllArgsConstructor
public class ResultDto {

	int ino;
	String type;
	String id;
	String ip;
	
	/**
	 * ino를 제외한 type, id, ip를 위한 생성자 직접 정의	
	 * @param type 로그인 결과 유형
	 * @param id 암호화 '된' 사용자 ID
	 * @param ip 시도한 IP
	 */
	public ResultDto(String type, String id, String ip) {
		this.type = type;
		this.id = id;
		this.ip = ip;
	};
	
}