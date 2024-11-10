package jj.stella.util;

import java.util.List;
import java.util.Map;

public class Verification {
	
	/** 비어있는지 확인 */
	public static Boolean isEmpty(Object obj) {
		
		if(obj == null) { return true; }
		if((obj instanceof String) && (((String)obj).trim().length() == 0)) { return true; }
		if(obj instanceof List) { return ((List<?>)obj).isEmpty(); }
		if(obj instanceof Map) { return ((Map<?, ?>) obj).isEmpty(); }
		if(obj instanceof Object[]) { return (((Object[])obj).length == 0); }
		
		return false;
		
	};
	public static Boolean isNotEmpty(Object obj) {
		return !isEmpty(obj);
	};
	
}