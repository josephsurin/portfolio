module.exports = {
    siteMetadata: {
        title: 'joseph\'s blog',
        siteUrl: 'https://jsur.in',
        description: 'CTF writeups',
        author: 'josephsurin',
        twitter: 'josep68_',
    },
    plugins: [
        'gatsby-plugin-react-helmet',
        {
            resolve: 'gatsby-source-filesystem',
            options: {
                name: 'posts',
                path: `${__dirname}/src/posts`
            }
        },
        {
            resolve: 'gatsby-source-filesystem',
            options: {
                name: 'images',
                path: `${__dirname}/src/images`
            }
        },
        'gatsby-transformer-sharp',
        'gatsby-plugin-sharp',
        {
            resolve: 'gatsby-transformer-remark',
            options: {
                plugins: [
                    {
                        resolve: 'gatsby-remark-prismjs',
                        options: { noInlineHighlight: true }
                    },
                    {
                        resolve: 'gatsby-remark-katex',
                        // options: { displayMode: false }
                    },
                    {
                        resolve: 'gatsby-remark-copy-linked-files',
                    },
                    {
                        resolve: 'gatsby-remark-images',
                        options: { maxWidth: 600 }
                    }
                ]
            }
        },
        {
            resolve: 'gatsby-plugin-mdx',
            options: {
                extensions: ['.mdx'],
                remarkPlugins: [
                    require('remark-math')
                ],
                rehypePlugins: [
                    [require('rehype-katex'), { strict: false }]
                ],
                gatsbyRemarkPlugins: [
                    {
                        resolve: 'gatsby-remark-prismjs',
                        options: { noInlineHighlight: true }
                    },
                    {
                        resolve: 'gatsby-remark-copy-linked-files',
                    },
                    {
                        resolve: 'gatsby-remark-images',
                        options: { maxWidth: 600 }
                    }
                ]
            }
        },
        'gatsby-plugin-sass'
    ],
}
