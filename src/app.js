import React from 'react'
import { HashRouter as Router, Route } from 'react-router-dom'
import Home from './Components/Home'

const App = () => {
	return (
		<Router>
			<div className="app-wrapper">
				<Route exact path="/" component={Home} />
				<Route path="/blog" render={() => <div>hey</div>} />
				<Route path="/portfolio" component={Home} />
			</div>
		</Router>
	)
}

export default App
