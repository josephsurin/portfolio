import React, { Component } from 'react'
import { Link } from 'react-router-dom'
import { formatDate } from '../../util'
import Tags from './tags'
const posts = require('../../posts/posts')

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
				<div className="blog-subtitle">I put stuff about school, my thoughts and my projects here.</div>
				<div className="posts">
					{posts.map(post => {
						let { attributes: { title, date, spoiler, tags }} = post
						return(
							<div key={title} className="post">
								<Link to={`/blog/${title}`}><div className="post-title">{title}</div></Link>
								<div className="post-date">{formatDate(date)}</div>
								<div className="post-spoiler">{spoiler}</div>
								<Tags tags={tags}/>
							</div>
						)
					})}
				</div>
			</div>
		)
	}
}
