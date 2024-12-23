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
import jj.stella.filter.auth.AuthDetails;

public class TokenUtil {
	
	/** Token 발급 로직 */
	public static String issueToken(
		String id, AuthDetails details,
		Key signKey, Key tokenKey,
		String issuer, String audience, long expired
	) throws JOSEException {
		
		JWTClaimsSet jwt = issueJwt(id, details, issuer, audience, expired);
		SignedJWT token = signJwt(jwt, signKey);
		JWEObject jwe = encryptJwt(token, tokenKey);
		
		return jwe.serialize();
		
	};
	
	/** JWT 토큰 발급 */
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
	
	/** JWT 서명 */
	private static SignedJWT signJwt(JWTClaimsSet jwt, Key key) throws JOSEException {
		
		SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwt);
		signedJwt.sign(new MACSigner(key.getEncoded()));
		
		return signedJwt;
		
	};
	
	/** JWT 암호화 = JWE */
	private static JWEObject encryptJwt(SignedJWT token, Key key) throws JOSEException {
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
			new Payload(token)
		);
		
		jweObject.encrypt(new DirectEncrypter(key.getEncoded()));
		return jweObject;
		
	};
	
	/** jti에서 ID와 사용자 기기 식별정보를 추출 */
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