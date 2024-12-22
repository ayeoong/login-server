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
	
	// ino를 제외하고 type, id, ip를 위한 생성자 직접 정의
	public ResultDto(String type, String id, String ip) {
		this.type = type;
		this.id = id;
		this.ip = ip;
	};
	
}