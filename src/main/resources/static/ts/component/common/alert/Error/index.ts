import Swal from "sweetalert2";

export const error = (html:string) => Swal.fire({ html, icon: `error` });
export const progressError = (html:string) => Swal.fire({ html, icon: `error`, timer: 2500, timerProgressBar: true });