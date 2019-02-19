import React from 'react'
import { HashRouter as Router, Route } from 'react-router-dom'
import Home from './Components/Home'
import Blog from './Components/Blog'
import PostPage from './Components/Blog/postPage'

const App = () => {
	return (
		<Router>
			<div className="app-wrapper">
				<Route exact path="/" component={Home} />
				<Route exact path="/blog" component={Blog} />
				<Route path="/blog/:title" component={PostPage} />
				<Route path="/portfolio" component={Home} />
			</div>
		</Router>
	)
}

export default App
