import React, { memo, useEffect, useRef } from "react";
import styled from "styled-components";

const Canvas = styled.canvas`
	width: 100vw;
	height: 100vh;
	background: linear-gradient(to right, #111, #0e0f19);
	overflow: hidden;
`;

/** 눈 속성 정의 */
interface Snowflake {
	/** x위치 */
	x:number;
	/** y위치 */
	y:number;
	/** 크기 */
	size:number;
	/** 떨어지는 속도 */
	speed:number;
	/** 눈 움직이는 방향 */
	dir:number;
}

export const Snow = memo(() => {

	const ref = useRef<HTMLCanvasElement>(null);
	const snow = useRef<Snowflake[]>([]);

	/** 캔버스 크기 동적 조정을 위한 함수 */
	const resizeCanvas = () => {

		const canvas = ref.current;
		if(canvas) {

			canvas.width = window.innerWidth;
			canvas.height = window.innerHeight;
			
			/** 캔버스 크기가 조정될 때마다 눈송이 다시 생성 */
			makeSnow();

		}

	};

	/** 눈송이를 생성하는 함수 */
	const makeSnow = () => {

		const canvas = ref.current;
		if(!canvas) return;

		/** 개수 */
		const snowflakes = 500;
		const snowData:Snowflake[] = Array.from({ length: snowflakes }, ():Snowflake => ({
			x: Math.random() * canvas.width,
			y: Math.random() * canvas.height,
			size: Math.random() * 1 + 2.0,
			speed: Math.random() * 0.3 + 0.2,
			dir: [-1, 1][Math.floor(Math.random() * 2)],
		}));

		snow.current = snowData;

	};

	useEffect(() => {

		const canvas = ref.current;
		if(!canvas) return;

		const ctx = canvas.getContext(`2d`);
		if(!ctx) return;

		/** 초기 캔버스 크기 조정 및 눈송이 생성 */
		resizeCanvas();
		/** 윈도우 크기 조정 시 캔버스 크기 조정 */
		window.addEventListener(`resize`, resizeCanvas);

		/** 눈송이 그리는 함수 */
		const drawSnow = () => {

			ctx.clearRect(0, 0, canvas.width, canvas.height);
			snow.current.forEach(data => {

				data.x += data.dir * data.speed;
				data.y += data.speed;

				/** 눈송이가 캔버스를 벗어난 경우 */
				if(data.x < 0 - data.size || data.x > canvas.width + data.size) {
					data.x = Math.random() * canvas.width;
					data.y = -data.size;
				} else if(data.y > canvas.height + data.size) {
					data.x = Math.random() * canvas.width;
					data.y = -data.size;
				}

				/** 그리기 시작 */
				ctx.beginPath();
				/** 눈송이(원) 그림 */
				ctx.arc(data.x, data.y, data.size, 0, Math.PI * 2);
				/** 색상, 투명도 */
				ctx.fillStyle = `rgba(255, 255, 255, 0.7)`;
				/** 그리기 완료 */
				ctx.fill();

			});

			/** 다음 프레임에서 눈송이를 다시 그림 */
			requestAnimationFrame(drawSnow);

		};

		/** 눈송이 그리기 시작 */
		drawSnow();

		return () => {
			window.removeEventListener(`resize`, resizeCanvas);
		};

	}, []);

	return <Canvas ref={ref} />;

});