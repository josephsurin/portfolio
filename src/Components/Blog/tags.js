import React from 'react'
import PropTypes from 'prop-types'

const Tags = ({ tags }) => {
	return (
		<div className="post-tags">
			{tags.split(',').map(tag => {
				return <div key={tag} className="post-tag">{tag}</div>
			})}
		</div>
	)
}

Tags.propTypes = {
	tags: PropTypes.string
}

export default Tags
