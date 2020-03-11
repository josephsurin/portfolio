import React from 'react'
import { Link } from 'gatsby'

import Layout from '../components/layout'
import SEO from '../components/seo'

import '../styles/404.sass'

const NotFoundPage = () => (
    <Layout>
        <SEO title="404 Not found" />
        <h1 className="four0four-msg">404 NOT FOUND</h1>
        <Link className="go-home" to="/">Go home</Link>
    </Layout>
)

export default NotFoundPage
