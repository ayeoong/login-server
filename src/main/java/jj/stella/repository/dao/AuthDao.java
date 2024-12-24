package jj.stella.repository.dao;

import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.ResultDto;
import jj.stella.entity.dto.UserDto;
import jj.stella.entity.vo.UserVo;

public interface AuthDao {
	
	/** 유저존재 확인 */
	public UserVo getUser(UserDto dto);
	/** 로그인 결과 저장 */
	public void regLoginResult(ResultDto dto);
//	/** 사용자의 마지막 접속일을 갱신 */
//	public void uptLoginDate(String id);
	
	/** Refresh Token 조회 */
	public int getRefreshToken(RefreshTokenDto dto);
	/** Refresh Token 저장 */
	public void regRefreshToken(RefreshTokenDto dto);
	/** Refresh Token 삭제 */
	public void delRefreshToken(RefreshTokenDto dto);
	
}