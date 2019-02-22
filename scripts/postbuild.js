const path = require('path')
const fs = require('fs')
const frontmatter = require('front-matter')
const stringifyObject = require('stringify-object')
const stringifyObjectOpts = { inlineCharacterLimit: 25 }
const { ncp } = require('ncp')

/* copy .md files and write metadata to posts.js */
const postsDir = path.resolve(__dirname, '../src/posts/')
const buildPostsDir = path.resolve(__dirname, '../build/posts/')

const postsMetadataFile = path.join(postsDir, 'index.js')

if(!fs.existsSync(buildPostsDir)) fs.mkdirSync(buildPostsDir)
var postsMetadata = fs.readdirSync(postsDir)
	.filter(postFilename => /.md$/.test(postFilename))
	.map(postFilename => {
		//copy .md files
		let source = path.join(postsDir, postFilename)
		let dest = path.join(buildPostsDir, postFilename)
		fs.copyFile(source, dest, err => { if(err) console.log(err) })

		//add metadata
		let post = fs.readFileSync(path.join(postsDir, postFilename)).toString()
		let { attributes } = frontmatter(post)
		return attributes
	})

//write metadata
var postsFile = `module.exports = ${stringifyObject(postsMetadata, stringifyObjectOpts)}`
fs.writeFileSync(postsMetadataFile, postsFile)

/* copy assets files */
const postsAssetsDir = path.resolve(__dirname, '../src/posts/assets/')
const buildAssetsDir = path.resolve(__dirname, '../build/posts/assets/')

if(!fs.existsSync(buildAssetsDir)) fs.mkdirSync(buildAssetsDir)
ncp(postsAssetsDir, buildAssetsDir, err => { if(err) console.log(err) })