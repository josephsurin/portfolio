const path = require('path')

exports.createPages = async({ actions, graphql, reporter }) => {
    const { createPage } = actions
    const blog_post_template = path.resolve('src/templates/blog-post.js')

    const res = await graphql(`
        {
            allMdx(sort: { order: DESC, fields: [frontmatter___date] }) {
                edges {
                    node {
                        fileAbsolutePath
                        frontmatter {
                            title
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

    var nodes = res.data.allMdx.edges
    var blog_nodes = nodes.filter(({ node }) => /\/posts\//.test(node.fileAbsolutePath))
    blog_nodes.forEach(({ node }, i) => {
        var prev = i === 0 ? null : blog_nodes[i-1].node
        var next = i === blog_nodes.length - 1 ? null : blog_nodes[i+1].node
        createPage({
            path: node.frontmatter.path,
            component: blog_post_template,
            context: { prev, next }
        })
    })
}
