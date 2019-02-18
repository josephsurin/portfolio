import React from 'react'
import PropTypes from 'prop-types'

const PostPage = ({ post }) => {
	return (
		<div className="post-page">
			<div className="post-title">{post.attributes.title}</div>
		</div>
	)
}

PostPage.propTypes = {
	post: PropTypes.object
}

export default PostPage