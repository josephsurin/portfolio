import React, { Component } from 'react'
import { Link } from 'react-router-dom'
import PropTypes from 'prop-types'

import { formatDate } from '../../util'
import Tags from './tags'

import { md } from './markdown'

import simpleStore from './simpleStore'

export default class PostPage extends Component {
	constructor(props) {
		super(props)

		var postPageProps = simpleStore.get('postPageProps')
		//prioritise using post data from state
		if(postPageProps) {
			this.state = {
				postMeta: Object.assign({}, postPageProps.postMeta),
				postBody: postPageProps.postBody
			}
		} else {
			this.fetchPostData()
		}

	}

	render() {
		let { postMeta: { title, date, tags }, postBody } = this.state
		return (
			<div className="post-page">
				<Link to="/blog" className="back-button">BACK</Link>
				<div className="post-title">{title}</div>
				<div className="post-date">{formatDate(date)}</div>
				<Tags tags={tags} />
				<hr />
				<div className="post-body" dangerouslySetInnerHTML={{ __html: md.render(postBody) }}/>
			</div>
		)
	}

	fetchPostData() {
		
	}
}

PostPage.propTypes = {
	postMeta: PropTypes.object.isRequired,
	postBody: PropTypes.string.isRequired
}