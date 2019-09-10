import React, { Component } from 'react'

export default class PrivatePosts extends Component {
    constructor(props) {
        super(props)

        this.state = { value: '' }
    }

    render() {
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
    }

    handleChange(e) {
        this.setState({ value: e.target.value })
    }

    handleSubmit(e) {
        e.preventDefault()
        var { value } = this.state
        //make the request and check if it exists
        //if it does, go to the post, else error alert
        alert('Invalid Password')
    }
}
