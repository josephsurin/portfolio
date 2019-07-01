import React from 'react'
import { Link } from 'react-router-dom'

const Home = () => {
    return (
        <div className="home-wrapper">
            <div className="home-main">
                <div className="title">Joseph Surin</div>
                <div className="subtitle">Student & Developer</div>
                <div className="link-buttons">
                    <a title="Github" href="https://github.com/josephsurin" className="icons link-button github-button"></a>
                    <a title="LinkedIn" href="https://www.linkedin.com/in/joseph-surin-0a756b17b/" className="icons link-button linkedin-button"></a>
                    <a title="Email" href="mailto:joseph.surin@gmail.com" className="icons link-button at-button"></a>
                    <a title="Resume (PDF)" href="#" className="icons link-button resume-button"></a>
                </div>
                <div className="work-buttons">
                    <Link to="/blog"><div className="work-button blog-button">BLOG</div></Link>
                    <Link to="/portfolio"><div className="work-button portfolio-button">PORTFOLIO</div></Link>
                </div>
            </div>
        </div>
    )
}

export default Home
