const NODE_MODE = process.env.NODE_ENV;

import axios from "axios";
import isEmpty from "lodash/isEmpty";
import React, { Fragment, lazy, useCallback, useRef, useState } from "react";

import { ClickEvent } from "../../config/type";
import { progressError, progressWarning } from "../common/alert";
import classNames from "classnames";

const DarkMode = lazy(() => import("../common/DarkMode"));

const InputID = lazy(() => import("../common/input").then(module => ({ default: module.String })));
const InputPassword = lazy(() => import("../common/input").then(module => ({ default: module.Password })));

const doc = window.document;
const Main = () => {

	/** 상태값 */
	const ref = useRef<HTMLParagraphElement>(null);
	const timeout = useRef<number |null>(null);

	const [ username, setUsername ] = useState<string>(``);
	const [ password, setPassword ] = useState<string>(``);
	const [ rememberMe, setRememberMe ] = useState<boolean>(false);

	/** 아이콘 클릭 시 Focus */
	const onClick = useCallback((e:ClickEvent) => {

		const target = e.currentTarget.parentNode as HTMLElement;
		Array.from(doc.getElementsByClassName(`login-input`)).map(v => {
			v.classList.remove(`on`)
		});
		
		if(target) {
			(target.lastChild as HTMLElement).focus();
			target.classList.add("on");
		}

	}, []);

	/** CapsLock 여부 */
	const onCapsLock = useCallback((isActive:boolean) => {
		if(ref.current) {

			clearTimeout(timeout.current ?? undefined);
			ref.current.style.display = isActive? `block`:`none`;

			if(isActive) {
				timeout.current = window.setTimeout(() => {
					if(ref.current)
						ref.current.style.display = `none`;
				}, 1500);
			}

		}
	}, []);
	
	/** 인수영역에 data( 상태값 )세팅을 하지 않으면 useEffect에서 찍어봤을 때 변경되지 않음. */
	const onId = useCallback((v:string) => {
		setUsername(v);
	}, [username]);
	const onPassword = useCallback((v:string) => {
		setPassword(v);
	}, [password]);
	const onRememberMe = useCallback(() => {
		setRememberMe(!rememberMe);
	}, [rememberMe]);

	/** JTI 생성 ( JWT Token ID - 기기의 고유 식별번호 생성을 위함. ) */
	const createJTI = useCallback(() => {
		return `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.replace(/[xy]/g, function(c) {
			let a = Math.random() * 16 | 0, v = c === `x` ? a : (a & 0x3 | 0x8);
			return v.toString(16);
		});
	}, []);
	
	/** 로그인 Action */
	const onLogin = useCallback((e:React.FormEvent<HTMLFormElement>) => {

		/** 새로고침 방지 */
		e.preventDefault();
		e.stopPropagation();

		/** 데이터 */
		if(!username)
			{ progressWarning(`ID를 입력해주세요.`); return; }
		if(!password)
			{ progressWarning(`비밀번호를 입력해주세요.`); return; }
		/** 기기의 고유 식별번호 */
		if(!localStorage.getItem(`device`))
			localStorage.setItem(`device`, createJTI());

		const data = new FormData();
		data.append(`username`, username);
		data.append(`password`, password);
		data.append(`device`, localStorage.getItem(`device`) || ``);
		data.append(`rememberMe`, rememberMe.toString()); // Remember Me 상태 추가
		axios(`/loginproc`, {
			method: `POST`, data,
			headers: {
				"Content-Type": `application/x-www-form-urlencoded`
			}
		}).then((res) => {

			const { redirect } = res.data;
			if(res.status === 200)
				window.location.href = redirect;

		}).catch((err) => {

			if(!isEmpty(err.response.data.str)) progressError(err.response.data.str)
			else progressError(`서버 및 데이터베이스 이슈발생 <br /> 관리자에게 연락부탁드립니다.`);

		});

	}, [ username, password, rememberMe ]);

	const [ noti, setNoti ] = useState<boolean>(true);
	return (
	<Fragment>
		<div className={`login-wrap`}>
			<div className={`login-box`}>
				<div className={`login-container`}>
					<div className={classNames(`login`, `shadow-3d`)}>



						<div className={`login-body`}>


							{/* <div className={`login-logo`}>
								<h1>{`St2lla Server`}</h1>
								<h1>{`St2lla Server`}</h1>
								<h1>{`St2lla Server`}</h1>
								<h1>{`St2lla Server`}</h1>
							</div> */}
							<div className={`login-welcome`}>
								<p>{`Welcome,`}</p>
								<p>{`Sign in to Continue !`}</p>
							</div>
							{noti && <div className={`login-notification`}>
								<div className={`noti-icon`}>
									<svg viewBox="0 0 24 24" fill="currentColor" className="svg-icon--material svg-icon" data-name="Material--Lock"><g fill="none"><path d="M0 0h24v24H0V0z"></path><path d="M0 0h24v24H0V0z" opacity="0.87"></path></g><path d="M6 20h12V10H6v10zm6-7c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2z" opacity="0.3"></path><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"></path></svg>

								</div>
								<div className={`noti-text`}>
									<div>
										<strong>{`ID: `}</strong>
										<span>{`Aasdfaseong`}</span>
									</div>
									<div>
										<strong>{`Password: `}</strong>
										<span>{`ascaeapg`}</span>
									</div>
								</div>
								<button type={`button`} className={`btn-close`} onClick={() => setNoti(false)} />
							</div>}
							<form onSubmit={onLogin}>
								<div className={`login-input`}>
									<InputID data={``} holder={`ID`}
										focus={true} onChange={onId} />
								</div>
								<div className={`login-input`}>
									<InputPassword data={``} holder={`Password`}
										onChange={onPassword} onCapsLock={onCapsLock} />
								</div>
								<p ref={ref} className={`capslock`}><strong>{`CapsLock`}</strong>{`이 켜져있습니다.`}</p>
								<div className={`remember${rememberMe? ` on`:``}`}>
									<span id={`remember`} onClick={onRememberMe}>
										<i className={`fas fa-check`} />
									</span>
									<label onClick={onRememberMe}>{`Remember Me`}</label>
								</div>
								{rememberMe && <p id={`auto-login`}>{`자동로그인은 1년간 유지됩니다.`}</p>}
								<button type={`submit`}>{`Login`}</button>
							</form>


						</div>




					</div>
				</div>
			</div>
		</div>
		{NODE_MODE && <DarkMode mode={NODE_MODE} />}
	</Fragment>
	);

};

export default React.memo(Main);