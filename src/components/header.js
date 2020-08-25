import { Link } from 'gatsby'
import React from 'react'

import '../styles/icomoon.css'
import '../styles/header.sass'
import wolf from '../images/wolf.jpg'

const Header = () => (
    <header>
        <div className="header-container">
            <Link to="/">
                <div className="picture">
                    <img src={wolf} className="picture-img"></img>
                </div>
                <div className="name">Joseph Surin</div>
            </Link>
            <div className="about">Computing & Software Systems @ The University of Melbourne<br/><br/>CTF Writeups/Projects/Random Stuff</div>
            <ul className="links">
                <a href="https://github.com/josephsurin"><li><i className="icon-github"></i>GitHub</li></a>
                <a href="https://www.linkedin.com/in/joseph-surin-0a756b17b/"><li><i className="icon-linkedin"></i>LinkedIn</li></a>
                <a href="mailto:joseph.surin@gmail.com"><li><i className="icon-envelop"></i>Email</li></a>
                <a href="https://t.me/josephsurin"><li><i className="icon-telegram"></i>Telegram</li></a>
            </ul>
        </div>
    </header>
)

export default Header
