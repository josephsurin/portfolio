import React from 'react'
import { Link } from 'gatsby'

import Layout from '../components/layout'
import SEO from '../components/seo'

import '../styles/about.sass'

const AboutPage = () => (
    <Layout>
        <SEO title="About | Joseph Surin" />
        <div className="about-container">
            <h1>About</h1>
            Hi, I'm Joseph. I study Computer Science at the University of Melbourne. I'm interested in cyber security and play CTFs with <a href="https://ctftime.org/team/140575">skateboarding dog</a> (and formerly, with <a href="https://ctftime.org/team/109523">misc</a> in 2020).
            <br/>
            <br/>

            You'll mostly find writeups for crypto CTF challenges here. You can find some other stuff I do on my GitHub.

            <br/>

            <h3>Links</h3>
            <ul>
                <li><a href="https://github.com/josephsurin"><i className="icon-github"></i>GitHub</a></li>
                <li><a href="https://www.linkedin.com/in/joseph-surin-0a756b17b/"><i className="icon-linkedin"></i>LinkedIn</a></li>
                <li><a href="mailto:joseph.surin@gmail.com"><i className="icon-envelop"></i>Email</a></li>
                <li><a href="https://t.me/josephsurin"><i className="icon-telegram"></i>Telegram</a></li>
                <li><a href="#"><i className="icon-discord"></i>joseph#8210</a></li>
            </ul>
        </div>
    </Layout>
)

export default AboutPage
