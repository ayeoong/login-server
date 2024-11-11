import React, { useEffect, useState, useRef, memo } from "react";

/** 별이 그려지는 간격 ( interval ) */
const DRAW_INTERVAL = 60;

/** Canvas에 그려질 각 별을 정의 */
class Star {

	/** 별 x좌표 ( 0 ~ width ) */
	x:number;
	/** 별 y좌표 ( 0 ~ height ) */
	y:number;
	/** 별의 반지름 ( 1 ~ rmax ) */
	r:number;
	/** x 이동거리 ( -xmax ~ xmax ) */
	dx:number;
	/** y 이동거리 ( -ymax ~ ymax ) */
	dy:number;
	/** 별의 생존시간 ( 반지름 크기에 비례 ) */
	hl:number;
	/** 현재 생존시간 ( 0 >>> hl >>> 0 ) */
	rt:number;
	/** 별의 노화속도 ( 1 ~ 2 ) */
	drt:number;
	/** 별의 음영범위 ( 0.4 ~ 0.6 ) */
	stop:number;

	/** 별의 설정 값 */
	settings: {
		/** 생존시간 */
		ttl:number;
		/** 별의 최대 x 이동거리 */
		xmax:number;
		/** 별의 최대 y 이동거리 */
		ymax:number;
		/** 별의 최소 반지름 */
		rmin:number;
		/** 별의 최대 반지름 */
		rmax:number;
		/** 별의 노화속도 */
		drt:number;
	};

	/** 캔버스의 2D 렌더링 컨텍스트 */
	context:CanvasRenderingContext2D;

	/** Star 객체를 생성, 초기화 */
	constructor(width:number, height:number, context:CanvasRenderingContext2D) {

		this.context = context;
		this.settings = {
			ttl: 8000, xmax: 5, ymax: 2,
			rmin: 5, rmax: 10, drt: 1
		};

		this.x = 0;
		this.y = 0;
		this.r = 0;
		this.dx = 0;
		this.dy = 0;
		this.hl = 0;
		this.rt = 0;
		this.drt = this.settings.drt;
		this.stop = 0;

		/** 너비와 높이를 기반으로 별의 속성을 리셋 */
		this.reset(width, height);

	}

	/** 별의 속성을 리셋하는 함수. 새 위치와 속성을 랜덤하게 설정 */
	reset(width:number, height:number) {
		this.x = width * Math.random();
		this.y = height * Math.random();
		this.r = ((this.settings.rmax - 1) * Math.random()) + 1;
		this.dx = (Math.random() * this.settings.xmax) * ((Math.random() >= 0.5)? 1 : -1);
		this.dy = (Math.random() * this.settings.ymax) * ((Math.random() >= 0.5)? 1 : -1);
		this.hl = (this.settings.ttl / DRAW_INTERVAL) * (this.r / this.settings.rmax);
		this.rt = 0;
		this.drt = Math.random() + 1;
		this.stop = (Math.random() * 0.2) + 0.4;
	}

	/** 별의 생명주기를 업데이트하고, 생명주기가 종료되면 별을 리셋하는 함수 */
	fade() {

		this.rt += this.drt;
		if(this.rt >= this.hl) {
			this.rt = this.hl;
			this.drt = -this.drt;
		} else if(this.rt <= 0)
			this.reset(this.context.canvas.width, this.context.canvas.height);

	}

	/** 캔버스에 별을 그리는 함수. 별의 현재 생명주기에 따라 밝기와 크기가 결정됨 */
	draw() {

		const transparent = this.rt / this.hl;
		this.context.beginPath();
		this.context.arc(this.x, this.y, this.r, 0, Math.PI * 2, true);
		this.context.closePath();

		const newr = this.r * transparent;
		const gradient = this.context.createRadialGradient(this.x, this.y, 0, this.x, this.y, (newr >= this.settings.rmin)? newr : this.settings.rmin);
		gradient.addColorStop(0.0, `rgba(255, 255, 255, ${transparent})`);
		gradient.addColorStop(this.stop, `rgba(121, 148, 237, ${transparent * 0.6})`);
		gradient.addColorStop(1.0, `rgba(121, 148, 237, 0)`);
		this.context.fillStyle = gradient;
		this.context.fill();

	}
	/** 별의 위치를 업데이트하는 함수. 별이 캔버스 경계를 넘어가면 반대 방향으로 이동 */
	move() {
		this.x += (1 - this.rt / this.hl) * this.dx;
		this.y += (1 - this.rt / this.hl) * this.dy;
		if(this.x > this.context.canvas.width || this.x < 0) this.dx = -this.dx;
		if(this.y > this.context.canvas.height || this.y < 0) this.dy = -this.dy;
	}

}

export const Stars = memo(() => {

	const ref = useRef<HTMLCanvasElement>(null);
	const [ star, setStar ] = useState<Star[]>([]);
	const [ viewport, setViewport ] = useState({
		width: window.innerWidth,
		height: window.innerHeight
	});

	/** 화면 크기가 변경될 때마다 화면의 너비, 높이 갱신 */
	useEffect(() => {
		const resize = () => setViewport({ width: window.innerWidth, height: window.innerHeight });
		window.addEventListener(`resize`, resize);
		return () => window.removeEventListener(`resize`, resize);
	}, []);

	/** 화면의 너비, 높이가 갱신되면 별들을 재배치 ( 초기화, 업데이트 ) */
	useEffect(() => {

		const canvas = ref.current;
		const context = canvas?.getContext(`2d`);
		if(canvas && context) {

			canvas.width = viewport.width;
			canvas.height = viewport.height;

			// 초기화, 업데이트
			const clearStars = () => {

				let cnt = 0;
				const newStars:Star[] = [];
				if(viewport.width > 1440) cnt = 15000;
				if(viewport.width > 768 && viewport.width <= 1440) cnt = 17500;
				if(viewport.width <= 768) cnt = 20000;

				for(let i = 0; i < (viewport.width * viewport.height) / cnt; i++) {
					if(i < star.length) newStars.push(star[i])
					else newStars.push(new Star(viewport.width, viewport.height, context));
				}

				return newStars;

			};

			setStar(clearStars());

		}

	}, [viewport]);

	/** 화면의 너비, 높이에 변화가 없을 때 별들을 주기적으로 그림 */
	useEffect(() => {

		const draw = () => {

			const context = ref.current?.getContext(`2d`);
			if(context) {
				context.clearRect(0, 0, viewport.width, viewport.height);
				star.forEach(particle => {
					particle.fade();
					particle.move();
					particle.draw();
				});
			}

		};

		const interval = setInterval(draw, DRAW_INTERVAL);
		return () => clearInterval(interval);

	}, [star, viewport]);

	return (
	<canvas ref={ref} id={`stars`} />
	);

});