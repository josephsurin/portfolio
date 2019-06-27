import React from 'react'

const Tags = ({ tags }) => {
	return (
		<div className="post-tags">
			{tags.split(',').map(tag => {
				return <div key={tag} className="post-tag">{tag}</div>
			})}
		</div>
	)
}

export default Tags
