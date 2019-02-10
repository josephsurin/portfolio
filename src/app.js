import React from 'react'

require('./styles/main.sass')

import Home from './Components/Home'

const App = () => {
	return (
		<div className="app-wrapper">
			<Home />
		</div>
	)
}

export default App
