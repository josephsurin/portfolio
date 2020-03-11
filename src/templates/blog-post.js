import React from 'react'
import { Link, graphql } from 'gatsby'

import Layout from '../components/layout'
import SEO from '../components/seo'
import Tags from '../components/tags'

import '../styles/md.sass'
import '../styles/post-page.sass'
import '../styles/prism-onedark.css'
import 'prismjs/plugins/command-line/prism-command-line.css'
import 'katex/dist/katex.min.css'

export default function Template({ data, pageContext }) {
    const { markdownRemark: post } = data
    const { prev, next } = pageContext
    return (
        <Layout>
            <SEO title={`${post.frontmatter.title} | Joseph Surin`} />
            <div className="post-page">
                <Link to="/" className="back-button">⬅ BACK</Link>
                <div className="post-title">{post.frontmatter.title}</div>
                <div className="post-date">{post.frontmatter.date}</div>
                <Tags tags={post.frontmatter.tags} />
                <hr />
                <div className="post-body" dangerouslySetInnerHTML={{ __html: post.html }}></div>
                <hr />
                <div className="blog-post-footer">
                    {prev && (
                        <Link
                            to={prev.frontmatter.path}
                            rel="prev"
                            className="prev-link"
                        > ← {prev.frontmatter.title}
                        </Link>
                    )}
                    {next && (
                        <Link
                            to={next.frontmatter.path}
                            rel="next"
                            className="next-link"
                        > {next.frontmatter.title} →
                        </Link>
                    )}
                </div>
            </div>
        </Layout>
    )
}

export const postQuery = graphql`
    query BlogPostByPath($path: String!) {
        markdownRemark(frontmatter: { path: { eq: $path } }) {
            html
            frontmatter {
                date(formatString: "MMMM DD, YYYY")
                path
                title
                tags
            }
        }
    }
`
