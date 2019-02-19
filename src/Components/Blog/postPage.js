import React, { Component } from 'react'
import { Link } from 'react-router-dom'
import PropTypes from 'prop-types'
import { formatDate } from '../../util'
import Tags from './tags'
const posts = require('../../posts/posts')

import { md } from './markdown'

export default class PostPage extends Component {
	constructor(props) {
		super(props)

		this.state = {
			post: posts.find(post => post.attributes.title == props.match.params.title)
		}
	}

	render() {
		var { attributes: { title, date, tags }, body } = this.state.post

		return (
			<div className="post-page">
				<Link to="/blog"><div className="back-button">BACK</div></Link>
				<div className="post-title">{title}</div>
				<div className="post-date">{formatDate(date)}</div>
				<Tags tags={tags} />
				<hr />
				<div className="post-body" dangerouslySetInnerHTML={{ __html: md.render(body) }}/>
			</div>
		)
	}
}

PostPage.propTypes = {
	match: PropTypes.object
}