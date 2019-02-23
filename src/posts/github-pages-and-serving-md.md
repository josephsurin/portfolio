= yaml =
title: Github Pages and serving md 
slug: github-pages-and-serving-md
date: 24/02/2019
tags: development
= yaml =

In case you haven't noticed, this blog, and many other blogs, use markdown to create blog posts. Markdown is a great tool for this purpose as it's easy and simple to write while being very extensible.

### YAML front matter

YAML front matter is a section of YAML placed at the top of a document and is a commonly used approach to storing metadata relating to the document it is in. In the case of blog posts, the data stored could be things like the title, date, tags, authors, etc. It can be used in any document and the relevant data can be extracted using a simple parser.

### Github Pages?

I use YAML front matter in my markdown blog posts, and while building this blog, I noticed a couple of strange behaviours exhibited by Github Pages (the static site hosting service that this blog is hosted on). I made a [repository](https://github.com/josephsurin/gh-pages-behaviour-test) to test my suspicions, but to summarise, here's what I found:

  - Github Pages _does_ serve basic .md documents with no YAML front matter without any problems
  - Github Pages _does not_ serve .md documents with YAML front matter (using the conventional `---` section delimiters)
  - Github Pages _does_ serve markdown documents with YAML front matter (again, with the conventional sectional delimiters), but only if the file extension is something other than .md, however, the YAML front matter section will be omitted.
  
Essentially, if you have a .md file with YAML front matter in it, Github Pages won't serve it; it will return a 404 error. However, if you change the extension from .md to something else, Github Pages will serve it, except, the YAML front matter will not be present.

### The workaround

With Github Pages being a static site hosting service and me not being able to modify the backend at all, I came up with a workaround for this issue. The trick is to use a section delimiter other than `---` for the YAML front matter section. This has the downside of being visible and ugly if you're rendering the .md file in a markdown editor or viewer such as on Github. But it still works as long as you have a front matter parser that checks for the delimiter you're using.