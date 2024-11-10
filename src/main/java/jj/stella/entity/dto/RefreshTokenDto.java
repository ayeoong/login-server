package jj.stella.entity.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenDto {

	/** 사용자 ID */
	private String id;
	/** 사용자 기기 식별번호 */
	private String device;
	/** Remember Me - Refresh Token */
	private String token;
	
}