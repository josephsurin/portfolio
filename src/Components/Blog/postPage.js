import React, { Component } from 'react'
import { Link } from 'react-router-dom'
import PropTypes from 'prop-types'

import { formatDate } from '../../util'
import Tags from './tags'

import { md } from './markdown'

import { simpleStore, fetchPostData } from './util'

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
		if(!this.state) {
			return <div className="loading"/>
		}
		let { postMeta: { title, date, tags }, postBody } = this.state
		console.log(title, date)
		return (
			<div className="post-page">
				<Link to="/blog" className="back-button">BACK</Link>
				<div className="post-title">{title}</div>
				<div className="post-date">{formatDate(date)}</div>
				<Tags tags={tags} />
				<hr />
				<div className="post-body" dangerouslySetInnerHTML={{ __html: md.render(postBody || '') }}/>
			</div>
		)
	}

	fetchPostData() {
		fetchPostData(this.props.match.params.slug).then(postPageProps => {
			this.setState({
				postMeta: Object.assign({}, postPageProps.postMeta),
				postBody: postPageProps.postBody
			})
		})
	}
}

PostPage.propTypes = {
	match: PropTypes.object.isRequired
}