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
		//copy .md files but use the extension .blogpost (gh-pages workaround)
		let source = path.join(postsDir, postFilename)
		let dest = path.join(buildPostsDir, postFilename)
		fs.copyFile(source, dest, err => { if(err) console.log(err) })

		//add metadata
		let post = fs.readFileSync(path.join(postsDir, postFilename)).toString()
		let { attributes } = frontmatter(post)
		return attributes
	})
	.sort((p1, p2) => {
		let { date: d1 } = p1
		let { date: d2 } = p2
		var [ day1, month1, year1 ] = d1.split('/')
		var [ day2, month2, year2 ] = d2.split('/')
		if(year1 > year2) return -1
		if(year2 > year1) return 1
		if(month1 > month2) return -1
		if(month2 > month1) return 1
		if(day1 > day2) return -1
		if(day2 > day1) return 1
	})

//write metadata
var postsFile = `module.exports = ${stringifyObject(postsMetadata, stringifyObjectOpts)}`
fs.writeFileSync(postsMetadataFile, postsFile)

/* copy assets files */
const postsAssetsDir = path.resolve(__dirname, '../src/posts/assets/')
const buildAssetsDir = path.resolve(__dirname, '../build/posts/assets/')

if(!fs.existsSync(buildAssetsDir)) fs.mkdirSync(buildAssetsDir)
ncp(postsAssetsDir, buildAssetsDir, err => { if(err) console.log(err) })