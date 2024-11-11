import Swal from "sweetalert2";

export const success = () => Swal.fire({ title: `Success !`, icon: `success` });
export const progressSuccess = () => Swal.fire({ title: `Success !`, icon: `success`, timer: 1500, timerProgressBar: true });