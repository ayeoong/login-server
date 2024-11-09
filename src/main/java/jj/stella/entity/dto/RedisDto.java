package jj.stella.entity.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RedisDto {

	/** 관련 유저의 고유번호 */
	private int ino;
	/** 테이블 구분자 */
	private String section;
	/** 내용 */
	private String conts;
	/** 데이터 생성일 */
	private String date;
	
}