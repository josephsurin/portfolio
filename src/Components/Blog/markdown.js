const mk = require('@iktakahiro/markdown-it-katex')
const mde = require('markdown-it-emoji')
const mdc = require('markdown-it-checkbox')
const hljs = require('highlight.js')
import 'highlight.js/styles/atom-one-dark.css'
import 'katex/dist/katex.min.css'

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
}).use(mde).use(mk).use(mdc)
