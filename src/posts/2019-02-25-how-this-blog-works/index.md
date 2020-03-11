---
path: /post/2019-02-25-how-this-blog-works
title: How this blog works
date: 2019-02-25
tags: development
---

> Update: As of 11/03/2020, this blog has been rebuilt with [GatsbyJS](gatsbyjs.org/)! Although it was fun and educational implementing my own sort of content management system, using something like GatsbyJS makes things a lot easier.

This blog is completely static and is hosted on Github Pages. It's a simple SPA built primarily using React, and webpack+babel for bundling the source code which lives in [this repository](https://github.com/josephsurin/portfolio). The routing is done on the front end using React Router.

Being unable to access the back end and decide what is served for certain paths, I had to come up with another way of serving my blog's markdown posts without the need of making a new folder and html file for each of them; I wanted a simple way to let me write a post in markdown, run a build script, and commit and push the changes for publishing.

I had considered using something like Jekyll, but I wanted something very basic and minimal that I built by myself from scratch.

## First Approach

The first method I tried involved using a [custom webpack loader for markdown files](https://github.com/webpack-contrib/yaml-frontmatter-loader) and requiring them all in one place, from which I could export them to be used whereever it needed to be used. Essentially, I would have an extra `.js` file sitting somewhere that had the contents:

```javascript
module.exports = [
  require('./post1.md'),
  require('./post2.md'),
  require('./post3.md') //and so on
]
```

This required me to add a line to this file whenever I wanted to add a post. At first, this didn't seem to be much of an issue and I thought I'd be able to write a simple script to automate that for me. However, something that bugged me was the fact that the entire `.md` file's contents for each and every post would be bundled into the resulting bundle javascript file that is served (since that's how the webpack md loader I was using works). For a couple of small posts, this wouldn't pose too much of a problem, but as the posts get bigger and larger in numbers, this would start to take a toll on the bundle size.

Because of this, I started looking for a different way I could approach this problem.

## Second Approach

I had also taken it for granted while using the first approach, that the metadata for each post was nicely formatted for me in the exported array thanks to the md loader I was using. I would need the metadata if I wanted to make an [index page](https://josephsurin.js.org/#/blog) that shows all the blog posts without the actual contents. I had taken a liking to YAML front matter for embedding simple metadata within my markdown files (see [this post](https://josephsurin.js.org/#/blog/github-pages-and-serving-md)), but having the metadata inside the md files would mean that I'd have to access the file if I were to read the metadata.  To solve this, I wrote a [simple script](https://github.com/josephsurin/portfolio/blob/master/scripts/prebuild.js) that should be run before building. This script reads all the posts and extracts the metadata needed for the index page into a javascript file which then exports the metadata. This file had the contents:

```javascript
module.exports = [
  {
    title: 'Post 1',
    slug: 'post1',
    date: '01/01/2000',
    tags: 'tag1,tag2'
  },
  {
    title: 'Post 2',
    slug: 'post2',
    date: '01/01/2001',
    tags: 'tag1,tag2,tag3'
  } //and so on
]
```

I decided that this was tolerable as only the metadata is included, and I'm not required to manually write extra things when I want to make a post.

To actually 'serve' the file, I use the javascript [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) to make a request to the location where all the posts get moved (automated using the aforementioned pre build script). This way, the post body is not redundantly included in the bundle, and the post is only loaded when the user actually needs it; the way things should be.
