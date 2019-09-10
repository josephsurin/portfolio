import React from 'react'
import { HashRouter as Router, Route } from 'react-router-dom'
import loadable from '@loadable/component'
const Home = loadable(() => import('./Components/Home'))
const Blog = loadable(() => import('./Components/Blog'))
const PostPage = loadable(() => import('./Components/Blog/postPage'))
const PrivatePosts = loadable(() => import('./Components/PrivatePosts'))

const App = () => {
    return (
        <Router>
            <div className="app-wrapper">
                <Route exact path="/" component={Home} />
                <Route exact path="/blog" component={Blog} />
                <Route path="/blog/:slug" component={PostPage} />
                <Route path="/portfolio" component={Home} />
                <Route path="/privateposts" component={PrivatePosts} />
            </div>
        </Router>
    )
}

export default App
