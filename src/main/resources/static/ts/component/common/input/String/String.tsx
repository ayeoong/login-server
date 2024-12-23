import React, { Fragment, memo, useCallback, useEffect, useRef, useState } from "react";

type Define = {data:string; holder:string; focus?:boolean; onChange:(v:string) => void;}|
	{data:string; holder:string; focus:boolean; onChange:(v:string) => void;};

export const String = memo(({ data, holder, focus, onChange }:Define) => {

	const ref = useRef<HTMLInputElement>(null);
	const [ str, setStr ] = useState<string>(``);
	const [ isFirst, setFirst ] = useState<boolean>(true);

	/** focus on */
	const onFocus = useCallback((e:React.FocusEvent<HTMLInputElement>):void => {
		const node = e.currentTarget.parentNode;
		if(node instanceof Element)
			node.classList.add(`on`);
	}, []);
	/** focus out */
	const onBlur = useCallback((e:React.FocusEvent<HTMLInputElement>):void => {
		const node = e.currentTarget.parentNode;
		if(node instanceof Element)
			node.classList.remove(`on`);
	}, []);
	/** change value */
	const onStr = useCallback((e:React.ChangeEvent<HTMLInputElement>):void => {

		const { value } = e.target;
		setStr(value);

	}, []);

	/**
	 * 검색 양식이라면 focus라는 Props가 설정되고,
	 * 해당값이 true라면 Open상태이기 때문에 자동 focus되도록 함.
	*/
	useEffect(() => {
		if(ref.current && focus)
			ref.current.focus();
	}, [focus]);

	/** 초기값 */
	useEffect(() => {

		setStr(data);

		/** 첫 로딩 상태 해제 */
		setFirst(false);

	}, [data]);

	/** 입력값 세팅 ( 부모컴포넌트 ) */
	useEffect(() => {

		/** 첫 로딩이 아닐 때만 onChange 호출 */
		if(!isFirst)
			onChange(str);

	}, [str]);

	return (
	<Fragment>
		<input ref={ref}
			className={`input-control`}
			type={`text`}
			value={str}
			placeholder={holder}
			onFocus={onFocus}
			onBlur={onBlur}
			onChange={onStr}
			spellCheck={false}
		/>
		<label>{holder}</label>
	</Fragment>
	);

});

export default React.memo(String);