import React, { Component } from 'react'
import { formatDate } from '../../util'
import Tags from '../Blog/tags'

import { md } from '../Blog/markdown'
const frontmatter = require('front-matter')
const sha1 = require('sha1')

export default class PrivatePosts extends Component {
    constructor(props) {
        super(props)

        this.state = { value: '', postData: null }
    }

    render() {
        var { postData } = this.state
        if(!postData) {
            return (
                <div className="private-posts-prompt">
                    <form className="private-post-password-form" onSubmit={this.handleSubmit.bind(this)}>
                        <label>
                        Password (flag) <br/>
                        <input type="text" name="password" onChange={this.handleChange.bind(this)}/>
                        </label>
                        <input type="submit" value="Submit"/>
                    </form>
                </div>
            )
        } else {
            var { attributes: { title, date, tags }, body } = postData
            return (
                <div className="post-page">
                    <div className="post-title">{title}</div>
                    <div className="post-date">{formatDate(date)}</div>
                    <Tags tags={tags} />
                    <hr />
                    <div className="post-body" dangerouslySetInnerHTML={{ __html: md.render(body) }}/>
                </div>
            )

        }
    }

    handleChange(e) {
        this.setState({ value: e.target.value })
    }

    handleSubmit(e) {
        e.preventDefault()
        var { value } = this.state
        const pps_url = 'https://privatepost-server.herokuapp.com/files/' + sha1(value)
        fetch(pps_url)
            .then(x => {
                if(x.status == 404) {
                    alert('Invalid Password')
                    return null
                } else {
                    return x.text()
                }
            })
            .then(rawMD => {
                if(rawMD) this.setState({ postData: frontmatter(rawMD) })    
            })
    }
}
