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
            </Link>
            <ul className="links">
                <Link to="/"><li>Home</li></Link>
                <Link to="/about"><li>About</li></Link>
            </ul>
        </div>
    </header>
)

/*
                <a href="https://github.com/josephsurin"><li><i className="icon-github"></i>GitHub</li></a>
                <a href="https://www.linkedin.com/in/joseph-surin-0a756b17b/"><li><i className="icon-linkedin"></i>LinkedIn</li></a>
                <a href="mailto:joseph.surin@gmail.com"><li><i className="icon-envelop"></i>Email</li></a>
                <a href="https://t.me/josephsurin"><li><i className="icon-telegram"></i>Telegram</li></a>
*/

export default Header
