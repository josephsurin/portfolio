import React from 'react'

const Home = () => {
	return (
		<div className="home-wrapper">
			<div className="home-main">
				<div className="title">Joseph Surin</div>
				<div className="subtitle">Student & Developer</div>
				<div className="link-buttons">
					<a title="Github" href="https://github.com/fumetsuu" className="fa-brands link-button github-button">github</a>
					<a title="LinkedIn" href="https://www.linkedin.com/in/joseph-surin-0a756b17b/" className="fa-brands link-button linkedin-button">linkedin</a>
					<a title="Email" href="mailto:joseph.surin@gmail.com" className="fa-solid link-button at-button">at</a>
					<a title="Resume (PDF)" href="#" className="fa-solid link-button resume-button">file-alt</a>
				</div>
			</div>
		</div>
	)
}

export default Home
