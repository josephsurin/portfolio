//import assets
require('./assets/hexgeometry.png')
require('./assets/hexlabelled.png')
require('./assets/hexdv.png')

//i don't know any other way for a static website with webpack...
module.exports = [
	require('./generating-hexagons-with-svg.md')
].reverse()