package jj.stella.repository.dao;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import jakarta.annotation.Resource;
import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.ResultDto;
import jj.stella.entity.dto.UserDto;
import jj.stella.entity.vo.UserVo;

@Repository
public class AuthDaoImpl implements AuthDao {
	
	@Resource(name="sqlSessionTemplate")
	private SqlSession sqlSession;
	
	public void setSqlSession(SqlSession sqlSession) {
		this.sqlSession = sqlSession;
	};

	/** 유저존재 확인 */
	@Override
	public UserVo getUser(UserDto dto) {
		return sqlSession.selectOne("getUser", dto);
	};
	/** 로그인 결과 저장 */
	@Override
	public void regLoginResult(ResultDto dto) {
		sqlSession.insert("regLoginResult", dto);
	};
//	/** 사용자의 마지막 접속일을 갱신 */
//	@Override
//	public void uptLoginDate(String id) {
//		sqlSession.update("uptLoginDate", id);
//	};
	
	/** Refresh Token 조회 */
	@Override
	public int getRefreshToken(RefreshTokenDto dto) {
		return sqlSession.selectOne("getRefreshToken", dto);
	};
	/** Refresh Token 저장 */
	@Override
	public void regRefreshToken(RefreshTokenDto dto) {
		sqlSession.insert("regRefreshToken", dto);
	};
	/** Refresh Token 삭제 */
	@Override
	public void delRefreshToken(RefreshTokenDto dto) {
		sqlSession.delete("delRefreshToken", dto);
	};
	
}