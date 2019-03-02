(function suAnalyticsInitialise() {
	const API_URL = 'https://su-analytics.herokuapp.com/api'
	function sendAnalyticsReq() {
		var url = window.location.href
		if(url[url.length - 1] == '/') url = url.slice(0, url.length - 1)
		var postBody = {
			query: `mutation {
				addVisit(url: "${url}") {
					_id
				}
			}`
		}
		fetch(API_URL, {
			method: 'POST',
			body: JSON.stringify(postBody),
			headers: { 'Content-Type': 'application/json' }
		}).then(() => {
			console.log('sent sa req ', url)
		})
	}
	window.onload = sendAnalyticsReq
	window.onhashchange = sendAnalyticsReq
})()