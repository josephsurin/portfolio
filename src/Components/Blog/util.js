/* SIMPLE STORE */
class SimpleStore {
	constructor() {
		this.state = {}
	}

	set(k, v) {
		this.state[k] = v
	}

	get(k) {
		return this.state[k]
	}
}

export const simpleStore = new SimpleStore()

/* FETCH POST DATA */
const rp = require('request-promise')
const postsBuildDir = 'posts/'
const frontmatter = require('front-matter')

export function fetchPostData(slug) {
	return new Promise((resolve, reject) => {
		const postFilepath = `${postsBuildDir}${slug}.blogpost`
		console.log('fetching ', postFilepath)
		rp(postFilepath).then(rawMD => {
			console.log('rawMD: ', rawMD)
			let { attributes, body } = frontmatter(rawMD)
			let postPageProps = {
				postMeta: attributes,
				postBody: body
			}
			return resolve(postPageProps)
		}).catch(reject)
	})
}