import React, { Fragment, memo, useCallback, useEffect, useRef, useState } from "react";

interface Define {data:string; holder:string; onChange:(v:string) => void; onCapsLock:(v:boolean) => void;};
export const Password = memo(({ data, holder, onChange, onCapsLock }:Define) => {

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

	/** key down */
	const onKeyDown = useCallback((e:React.KeyboardEvent<HTMLInputElement>):void => {

		const key = e.key;
		const capslock = e.getModifierState(`CapsLock`);

		/** CapsLock 상태 + 알파벳 키를 누를 때 */
		if(capslock && ((key >= `A` && key <= `Z`) || (key >= `a` && key <= `z`)))
			onCapsLock(true);
		else onCapsLock(false);

	}, []);

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
			type={`password`}
			value={str}
			placeholder={holder}
			onFocus={onFocus}
			onBlur={onBlur}
			onChange={onStr}
			onKeyDown={onKeyDown}
			spellCheck={false}
		/>
		<label>{holder}</label>
	</Fragment>
	);

});