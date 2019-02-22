import React, { Component } from 'react'
import { Link } from 'react-router-dom'
import PropTypes from 'prop-types'

import { formatDate } from '../../util'
import Tags from './tags'

const posts = require('../../posts')
const postsBuildDir = 'posts/'

const frontmatter = require('front-matter')
import { md } from './markdown'

export default class PostPage extends Component {
	constructor(props) {
		super(props)

		this.state = {
			postMeta: posts.find(post => post.slug == props.match.params.slug),
			postBody: null
		}

		this.fetchPostBody()
	}

	render() {
		var { postMeta: { title, date, tags }, postBody } = this.state

		return (
			<div className="post-page">
				<Link to="/blog"><div className="back-button">BACK</div></Link>
				<div className="post-title">{title}</div>
				<div className="post-date">{formatDate(date)}</div>
				<Tags tags={tags} />
				<hr />
				<div className="post-body" dangerouslySetInnerHTML={{ __html: md.render(postBody || '') }}/>
			</div>
		)
	}

	fetchPostBody() {
		const postFilepath = `${postsBuildDir}${this.props.match.params.slug}.md`
		fetch(postFilepath)
			.then(res => res.text())
			.then(rawMD => {
				let { body } = frontmatter(rawMD)
				this.setState({ postBody: body })
			})
	}
}

PostPage.propTypes = {
	match: PropTypes.object.isRequired
}