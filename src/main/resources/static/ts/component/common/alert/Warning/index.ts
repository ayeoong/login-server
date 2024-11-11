import Swal from "sweetalert2";

export const warning = (html:string) => Swal.fire({ html, icon: `warning` });
export const progressWarning = (html:string) => Swal.fire({ html, icon: `warning`, timer: 2500, timerProgressBar: true });

/** Swal 확인 여부창 */
export const confirmWarning = (html:string) => {
	/** return한 이유는 호출 후 .then으로 후처리하기 위함. */
	return Swal.fire({
		html, icon: `warning`,
		showCancelButton: true,
		confirmButtonText: `OK`, cancelButtonText: `Cancel`,
		confirmButtonColor: `#2189ff`, cancelButtonColor: `#000000`
	});
};