import React, { useState, useCallback, useEffect } from "react";
import isEmpty from "lodash/isEmpty";

const InputPassword = ({ name, holder, data, change, capslock }) => {

	const [ iv, setIv ] = useState<string>(data || "" as string);

	/** focus on */
	const onFocus = useCallback((e:any) => {e.currentTarget.parentNode.classList.add("on")}, []);
	/** focus out */
	const onBlur = useCallback((e:any) => {e.currentTarget.parentNode.classList.remove("on")}, []);
	/** change value */
	const onChange = useCallback((e:any) => {
		const { value } = e.target;
		setIv(value);
	}, []);
	const onKeyDown = useCallback((e:any) => {
		
		const code = e.keyCode;
		if(code === 20 && e.getModifierState("CapsLock"))
			capslock(true)
		else if(((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) && e.getModifierState("CapsLock"))
			capslock(true);
		else capslock(false);
		
	}, []);

	/** 자동완성 지원 */
	const onInput = useCallback((e:any) => {
		
		const { value } = e.target;
		// 값이 현재 상태와 다를 때만 상태를 업데이트
		if(value !== iv)
			setIv(value);

	}, [iv]);

	/** 초기값 */
	useEffect(() => {
		if(!isEmpty(data)) setIv(data);
		else setIv("");
	}, [data]);

	/** 입력값 세팅 ( 부모컴포넌트 ) */
	useEffect(() => {
		change({ name, iv });
	}, [iv]);

	return (
		<input
			id={name}
			type={`password`}
			value={iv}
			placeholder={holder}
			onFocus={onFocus}
			onBlur={onBlur}
			onInput={onInput}
			onChange={onChange}
			onKeyDown={onKeyDown}
			spellCheck={false}
		/>
	);

}

export default React.memo(InputPassword);