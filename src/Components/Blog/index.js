import React, { Component } from 'react'
const posts = require('../../posts/posts')

import PostPage from './postPage'

export default class Blog extends Component {
	constructor(props) {
		super(props)

		this.state = {
			posts
		}

	}

	render() {
		let { posts } = this.state
		return (
			<div className="blog-container">
				<div className="blog-header">
					Personal blog by Joseph Surin
				</div>
				<div className="posts">
					{posts.map(post => {
						let { attributes: { title, date, spoiler, tags }} = post
						return(
							<div key={title} className="post">
								<div className="post-title">{title}</div>
								<div className="post-date">{date}</div>
								<div className="post-spoiler">{spoiler}</div>
								<div className="post-tags">{tags}</div>
							</div>
						)
					})}
				</div>
			</div>
		)
	}
}
