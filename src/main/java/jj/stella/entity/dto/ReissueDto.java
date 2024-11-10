package jj.stella.entity.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ReissueDto {

	/** 사용자 ID */
	private String id;
	/** 사용자 IP */
	private String ip;
	/** 사용자 AGENT */
	private String agent;
	/** 사용자 기기 고유번호 */
	private String device;
	
}