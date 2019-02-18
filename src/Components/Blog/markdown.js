const mk = require('@neilsustc/markdown-it-katex')
const mde = require('markdown-it-emoji')
const hljs = require('highlight.js')

export const md = require('markdown-it')({
	html: true,
	typographer: true,
	highlight: (str, lang) => {
		if(lang && hljs.getLanguage(lang)) {
			try {
				return `<pre class="hljs"><span class="md-code-lang">${lang}</span><code>${hljs.highlight(lang, str, true).value}</code></pre>`
			} catch (err) { console.log( err) }
		}

		return `<pre class="hljs"><span class="md-code-lang">${lang}</span><code>${md.utils.escapeHtml(str)}</code></pre>`
	}
}).use(mde).use(mk)
