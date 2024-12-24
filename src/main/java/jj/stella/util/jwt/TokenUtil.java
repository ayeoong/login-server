package jj.stella.util.jwt;

import java.security.Key;
import java.util.Date;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jj.stella.entity.dto.RefreshTokenDto;
import jj.stella.entity.dto.ReissueDto;
import jj.stella.filter.auth.AuthDetails;

public class TokenUtil {
	
	/**
	 * JWE 발급 로직을 수행하는 메서드
	 * 
	 * @param id        사용자 식별자
	 * @param details   사용자 인증 관련 상세 정보
	 * @param signKey   JWT 서명에 사용될 키
	 * @param tokenKey  JWT 암호화에 사용될 키
	 * @param issuer    토큰 발급자
	 * @param audience  토큰 수신자
	 * @param expired   토큰 만료 시간 (밀리초 단위)
	 * 
	 * @return JWE( 암호화된 JWT ) 반환
	 * */
	public static String issueJWE(
		String id, AuthDetails details,
		Key signKey, Key tokenKey,
		String issuer, String audience, long expired
	) throws JOSEException {
		
		JWTClaimsSet jwt = issueJwt(id, details, issuer, audience, expired);
		SignedJWT token = signJwt(jwt, signKey);
		JWEObject jwe = encryptJwt(token, tokenKey);
		
		return jwe.serialize();
		
	};
	
	/**
	 * JWT 토큰을 발급하는 메서드
	 * 
	 * @param id            사용자 식별자
	 * @param details       사용자 인증 추가정보 - AuthDetails
	 * @param issuer        토큰 발급자
	 * @param audience      토큰 수신자
	 * @param expired       토큰 만료 시간 ( 밀리초 단위 )
	 * 
	 * @return 생성된 JWTClaimsSet 객체
	 * */
	private static JWTClaimsSet issueJwt(
		String id, AuthDetails details,
		String issuer, String audience, long expired
	) {
		
		Date now = new Date();
		String jti = id + "::" + details.getDevice();
		return new JWTClaimsSet.Builder()
				.issuer(issuer)
				.subject(id)
				.audience(audience)
				.jwtID(jti)
				.expirationTime(new Date(now.getTime() + expired))
				.claim("ip", details.getIp())
				.claim("agent", details.getAgent())
				.claim("device", details.getDevice())
				.build();
		
	};
	
	/**
	 * JWE 재발급 로직을 수행하는 메서드
	 * 
	 * @param dto       재발급에 필요한 객체( ID, Device, Agent )
	 * @param signKey   JWT 서명에 사용될 키
	 * @param tokenKey  JWT 암호화에 사용될 키
	 * @param issuer    토큰 발급자
	 * @param audience  토큰 수신자
	 * @param expired   토큰 만료 시간 ( 밀리초 단위 )
	 * 
	 * @return JWE( 암호화된 JWT ) 반환
	 * */
	public static String reissueJWE(
		ReissueDto dto, Key signKey, Key tokenKey,
		String issuer, String audience, long expired
	) throws JOSEException {
		
		JWTClaimsSet jwt = reissueJwt(dto, issuer, audience, expired);
		SignedJWT token = signJwt(jwt, signKey);
		JWEObject jwe = encryptJwt(token, tokenKey);
		
		return jwe.serialize();
		
	};
	
	/**
	 * JWT 토큰을 재발급하는 메서드
	 * 
	 * @param dto       재발급에 필요한 객체( ID, Device, Agent )
	 * @param issuer    토큰 발급자
	 * @param audience  토큰 수신자
	 * @param expired   토큰 만료 시간 ( 밀리초 단위 )
	 * 
	 * @return 생성된 JWTClaimsSet 객체
	 * */
	private static JWTClaimsSet reissueJwt(ReissueDto dto, String issuer, String audience, long expired) {
		
		Date now = new Date();
		/** jti는 "로그인한 사용자의 ID::사용자 기기 식별번호"로 설정 */
		String jti = dto.getId() + "::" + dto.getDevice();
		return new JWTClaimsSet.Builder()
				.issuer(issuer)
				.subject(dto.getId())
				.audience(audience)
				.jwtID(jti)
				.expirationTime(new Date(now.getTime() + expired))
				.claim("ip", dto.getIp())
				.claim("agent", dto.getAgent())
				.claim("device", dto.getDevice())
				.build();
		
	};
	
	/**
	 * JWT 서명을 위한 메서드
	 * 
	 * @param jwt    서명할 JWTClaimsSet 객체
	 * @param key    서명에 사용할 키
	 * 
	 * @return 서명된 JWT 객체( SignedJWT )
	 * */
	private static SignedJWT signJwt(JWTClaimsSet jwt, Key key) throws JOSEException {
		
		SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwt);
		signedJwt.sign(new MACSigner(key.getEncoded()));
		
		return signedJwt;
		
	};
	
	/**
	 * 서명된 JWT 암호화를 위한 메서드
	 * 
	 * @param token  서명된 JWT 객체( SignedJWT )
	 * @param key    암호화에 사용할 키
	 * 
	 * @return 암호화된 JWT 객체( JWEObject )
	 * */
	private static JWEObject encryptJwt(SignedJWT token, Key key) throws JOSEException {
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
			new Payload(token)
		);
		
		jweObject.encrypt(new DirectEncrypter(key.getEncoded()));
		return jweObject;
		
	};
	
	/**
	 * JTI로부터 ID와 사용자 기기 식별정보를 추출하는 메서드
	 * 
	 * @param template    RestTemplate 객체
	 * @param headers     HTTP 헤더 정보
	 * @param JTI_SERVER  JTI 정보를 요청할 서버의 URL
	 * 
	 * @return RefreshTokenDto 객체, ID와 기기 정보, Agent를 포함
	 */
	public static RefreshTokenDto getJTI(RestTemplate template, HttpHeaders headers, String JTI_SERVER) {
		
		RefreshTokenDto dto = new RefreshTokenDto();
		HttpEntity<String> entity = new HttpEntity<>("", headers);
		ResponseEntity<String> res = template.exchange(JTI_SERVER, HttpMethod.GET, entity, String.class);
		
		String[] split = res.getBody().split("::");
		if(split.length < 2)
			return null;
		
		dto.setId(split[0]);
		dto.setDevice(split[1]);
		
		return dto;
		
	};
	
}