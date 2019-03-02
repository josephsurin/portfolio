= yaml =
title: Experimenting with GraphQL
slug: experimenting-with-graphql
date: 02/03/2019
tags: development,project,backend
= yaml =

## Overview

Out of curiosity and interest of learning more about [GraphQL](https://graphql.org/), I decided to build a _very_ simple web analytics system for my website. As a starting point, all it does is track the number of visitors and unique visitors, the IP address of the visitor and the time they visited a certain page.

### Set up

The web analytics system is a simple node.js server made using [express](http://expressjs.com/), connected to a [MongoDB](https://www.mongodb.com/) database (hosted for free using [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)). The GraphQL server, which I've decided to set up at the `/api` endpoint, is created using the [express-graphql](https://github.com/graphql/express-graphql) connect styled middleware package. Essentially, the server is set up so that `GET` and `POST` requests to the `/api` endpoint that have a valid GraphQL query are handled by the appropriate resolvers. The code below shows how `express-graphql` is used.

```javascript
const express = require('express')
const app = express()
const graphqlHTTP = require('express-graphql')

const schema = require('./graphql/schema')
const rootValue = require('./graphql/resolvers')

app.use('/api', graphqlHTTP({
  schema,
  rootValue
}))

app.listen(4000)
```

This code alone should be enough to set up a simple GraphQL server, given `schema` and `rootValue` are well defined.

### `schema` and `rootValue`

A schema and a bunch of resolvers are the only requirements for a simple GraphQL set up. I've built the schema for my simple project using the `graphql-js` built-in `buildSchema` function that takes a string that follows [GraphQL's schema language](https://graphql.org/learn/schema/) and creates a GraphQLSchema object from it which is required by the GraphQL server. The schema defines the types of data available as well as things such as queries (reading data) and mutations (creating/updating/deleting data). Note however, that although queries and mutations appear to be different, much like how `GET` requests shouldn't be used to modify data, while queries technically can mutate data on the server, anything that does mutate data should be explicitly labelled as a mutation to avoid confusion and unexpected behaviours. A simple schema for the basic web analytics service could look like this:

```javascript
const { buildSchema } = require('graphql')

module.exports = buildSchema(`
	type Visit {
		ip: String
		date: String!
	}

	type Page {
		_id: ID!
		visitorCount: Int!
		visitorCountUnique: Int!
		visits: [Visit]
	}

	type RootQuery {
		pages: [Page!]!
		page(url: String!): Page
	}

	type RootMutation {
		addVisit(url: String!): Page
	}

	schema {
		query: RootQuery
		mutation: RootMutation
	}
`)
```

On its own, the schema doesn't do much. In order to execute any kind of logic, resolvers need to be defined. A resolver is simply a function that is called when a query, mutation or some other kind of request is made to the GraphQL server. To specify resolvers with `express-graphql`, the `rootValue` property is passed to the constructor along with the `schema`. The `rootValue` variable is a Javascript object with keys that are named corresponding to the queries and mutations and values that are functions to be called when that certain query or mutation request is made. In our example, we have two queries named `pages` and `page` and one mutation named `addVisit`, so our `rootValue` object would look something like this:

```javascript
const rootValue = {
  pages: () => {
    //get pages from the database and return it
  },
  page: ({ url }) => {
    //get page with url as specified from the database and return it
  },
  addVisit: ({ url }, req) => {
    //mutate data in the database based on the given url and request object
    //e.g. increment visitor count and check if visitor is unique, etc.
  }
}
```

### Making use of it

I've decided to try and have a go at using the web analytics system on my website. To do that, I set up a project on [Heroku](http://heroku.com/) and wrote a simple [browser script](https://github.com/josephsurin/su-analytics/blob/master/browser-script/su-analytics.js) that I injected into my website's HTML. All the script does is send a request to the server to let it know that someone's visited the page. I may consider writing a simple frontend for the web analytics service to visualise the data, as well as more features beyond simply counting visitors, but seeing as the main purpose of this project was to learn and experiment, and also given that there are many free web analytics solutions already available, it seems like a waste of effort and time.

The repository for this project can be found [here](https://github.com/josephsurin/su-analytics).