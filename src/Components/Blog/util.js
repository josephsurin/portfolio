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

const postsBuildDir = 'assets/posts/'
const frontmatter = require('front-matter')

export function fetchPostData(slug) {
	return new Promise((resolve, reject) => {
		const postFilepath = `${postsBuildDir}${slug}.md`
		fetch(postFilepath)
			.then(res => res.text())
			.then(rawMD => {
				let { attributes, body } = frontmatter(rawMD)
				let postPageProps = {
					postMeta: attributes,
					postBody: body
				}
				return resolve(postPageProps)
			})
			.catch(reject)
	})
}