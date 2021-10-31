import React from 'react'
import { Link } from 'gatsby'

import Layout from '../components/layout'
import SEO from '../components/seo'

import '../styles/about.sass'

const AboutPage = () => (
    <Layout>
        <SEO title="About" />
        <div className="about-container">
            <h1>About</h1>
            Hi, I'm Joseph. I study Computer Science and Pure Mathematics at the University of Melbourne. I'm interested in cyber security and cryptography and play CTFs with <a href="https://ctftime.org/team/140575">skateboarding dog</a> (and formerly, with <a href="https://ctftime.org/team/109523">misc</a> in 2020).

            <br/>
            <br/>

            You'll mostly find writeups for crypto CTF challenges here. You can find some other stuff I do on my GitHub.

            <br/>
            <br/>

            Feel free to contact me for clarification/pointing out my mistakes on whatever I post, or just to chat :)

            <br/>

            <h3>Links</h3>
            <ul>
                <li><a href="https://github.com/josephsurin"><i className="icon-github"></i>josephsurin</a></li>
                <li><a href="https://twitter.com/josep68_"><i className="icon-twitter"></i>joseph68_</a></li>
                <li><a href="https://www.linkedin.com/in/joseph-surin/"><i className="icon-linkedin"></i>joseph-surin</a></li>
                <li><a href="#"><i className="icon-envelop"></i>contact[at]jsur.in</a></li>
                <li><a href="#"><i className="icon-discord"></i>joseph#8210</a></li>
            </ul>
        </div>
    </Layout>
)

export default AboutPage
