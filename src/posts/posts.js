//i don't know any other way for a static website with webpack...
module.exports = [
	require('./post1.md'),
	require('./post2.md')
].reverse()