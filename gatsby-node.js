const path = require('path')

exports.createPages = async({ actions, graphql, reporter }) => {
    const { createPage } = actions
    const mdxPostTemplate = path.resolve('src/templates/mdx-blog-post.js')
    const mdPostTemplate = path.resolve('src/templates/md-blog-post.js')

    const res = await graphql(`
        {
            allMarkdownRemark {
                edges {
                    node {
                        fileAbsolutePath
                        frontmatter {
                            title
                            date
                            path
                        }
                    }
                }
            }
            allMdx {
                edges {
                    node {
                        fileAbsolutePath
                        frontmatter {
                            title
                            date
                            path
                        }
                    }
                }
            }
        }
    `)

    if(res.errors) {
        return reporter.panicOnBuild('Error while creating blog pages (GraphQL query)')
    }

    var nodes = res.data.allMarkdownRemark.edges.concat(res.data.allMdx.edges)
    var blog_nodes = nodes.filter(({ node }) => /\/posts\//.test(node.fileAbsolutePath))
    blog_nodes.sort((p1, p2) => (new Date(p1.node.frontmatter.date)).getTime() - (new Date(p2.node.frontmatter.date)).getTime())
    blog_nodes.forEach(({ node }, i) => {
        var prev = i === 0 ? null : blog_nodes[i-1].node
        var next = i === blog_nodes.length - 1 ? null : blog_nodes[i+1].node
        const component = node.fileAbsolutePath.endsWith('.mdx') ? mdxPostTemplate
            : node.fileAbsolutePath.endsWith('.md') ? mdPostTemplate : null
        createPage({
            path: node.frontmatter.path,
            component,
            context: { prev, next }
        })
    })
}
