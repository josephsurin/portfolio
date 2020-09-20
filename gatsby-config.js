module.exports = {
    siteMetadata: {
        title: 'Joseph Surin Personal Blog',
        siteUrl: 'https://josephsurin.me',
        description: 'CTF Writeups, personal projects, random stuff',
        author: 'josephsurin',
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
            resolve: 'gatsby-plugin-mdx',
            options: {
                extensions: ['.mdx', '.md'],
                gatsbyRemarkPlugins: [
                    {
                        resolve: 'gatsby-remark-prismjs',
                        options: { noInlineHighlight: true }
                    },
                    {
                        resolve: 'gatsby-remark-katex',
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
