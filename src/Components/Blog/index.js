import React, { Component } from 'react'
import PropTypes from 'prop-types'

import { formatDate } from '../../util'
import Tags from './tags'

const postsBuildDir = 'posts/'
const posts = require('../../posts')

const frontmatter = require('front-matter')

import simpleStore from './simpleStore'
export default class Blog extends Component {
	constructor(props) {
		super(props)
		
		this.state = {
			posts,
			progressPercent: 0
		}

		this.readyPostPage = this.readyPostPage.bind(this)
	}

	render() {
		let { posts, progressPercent } = this.state
		return (
			<div className="blog-container">
				<div className="progress-loader" style={{ width: `${progressPercent}%` }}/>
				<div className="blog-header">
					Personal blog by Joseph Surin
				</div>
				<div className="blog-subtitle">I put stuff about school, my thoughts and my projects here.</div>
				<div className="posts">
					{posts.map(post => {
						let { title, slug, date, spoiler, tags } = post
						
						return(
							<div key={title} className="post">
								<div className="post-title" onClick={() => this.readyPostPage(slug)}>{title}</div>
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

	readyPostPage(slug) {
		this.setState({ progressPercent: 80 })
		const postFilepath = `${postsBuildDir}${slug}.md`
		fetch(postFilepath)
			.then(res => {
				this.setState({ progressPercent: 100 })
				return res.text()
			})
			.then(rawMD => {
				let { attributes, body } = frontmatter(rawMD)
				let postPageProps = {
					postMeta: attributes,
					postBody: body
				}
				simpleStore.set('postPageProps', postPageProps)
				setTimeout(() => {
					this.props.history.push(`blog/${slug}`)
				}, 100)
			})
	}
}

Blog.propTypes = {
	history: PropTypes.object
}