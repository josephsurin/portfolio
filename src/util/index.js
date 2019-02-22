const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'Decemember']

export function formatDate(ddmmyyyy) {
	var [ day, month, year ] = ddmmyyyy.split('/')
	return `${months[parseInt(month - 1)]} ${day}, ${year}`
}