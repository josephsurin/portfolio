import React from 'react'
import { HashRouter as Router, Route } from 'react-router-dom'
import Home from './Components/Home'
import Blog from './Components/Blog'

const App = () => {
	return (
		<Router>
			<div className="app-wrapper">
				<Route exact path="/" component={Home} />
				<Route path="/blog" component={Blog} />
				<Route path="/portfolio" component={Home} />
			</div>
		</Router>
	)
}

export default App
