import React from 'react'
import { Link, graphql } from 'gatsby'

import '../styles/blog-index.sass'

import SEO from '../components/seo'
// import Tags from '../components/tags'

import '../styles/header.sass'
import wolf from '../images/wolf.jpg'

const IndexPage = ({ data }) => {
    const { edges: postsMd } = data.allMarkdownRemark
    const { edges: postsMdx } = data.allMdx
    const posts = postsMd.concat(postsMdx)
    posts.sort((p1, p2) => (new Date(p2.node.frontmatter.date)).getTime() - (new Date(p1.node.frontmatter.date)).getTime())
    return (
        <>
            <SEO title="Home" />
            <div className="index-header">
                <div className="picture">
                    <img src={wolf} className="picture-img"></img>
                </div>
                <div className="bio">
                    <div>
                        Written by joseph (<a href="https://twitter.com/josep68_">Twitter</a>, <a rel="me" href="https://infosec.exchange/@josep68">Mastodon</a>)
                    </div>
                    <div>
                        CTF <span style={{opacity: 0.5}}>∪ </span>
                        Cryptography <span style={{opacity: 0.5}}>∪ </span>
                        Security <span style={{opacity: 0.5}}>∪ </span>
                        ?
                    </div>
                </div>
            </div>
            <div className="blog-container">
                <div className="posts">
                    {posts.map(({ node: post }) => (
                        <div key={post.frontmatter.title} className="post">
                            <Link className="post-title" to={post.frontmatter.path}>{post.frontmatter.title}</Link>
                            <div className="post-date">{post.frontmatter.date}</div>
                            {/*<Tags tags={post.frontmatter.tags} />*/}
                        </div>
                    ))}
                </div>
            </div>
        </>
    )
}

export const pageQuery = graphql`
    query NewsQuery {
        allMarkdownRemark(filter: { fileAbsolutePath: { regex: "\/posts\/" } }) {
            edges {
                node {
                    frontmatter {
                        title
                        date(formatString: "MMMM DD, YYYY")
                        path
                        tags
                    }
                }
            }
        }
        allMdx(filter: { fileAbsolutePath: { regex: "\/posts\/" } }) {
            edges {
                node {
                    frontmatter {
                        title
                        date(formatString: "MMMM DD, YYYY")
                        path
                        tags
                    }
                }
            }
        }
    }
`


export default IndexPage
