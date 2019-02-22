const mk = require('@iktakahiro/markdown-it-katex')
const mde = require('markdown-it-emoji')
const mdc = require('markdown-it-checkbox')
const prism = require('markdown-it-prism')
import './prism-onedark.css'
import 'katex/dist/katex.min.css'

export const md = require('markdown-it')({
	html: true,
	typographer: true,
	langPrefix: 'codeblock language-',
	highlight: (str, lang) => {
		console.log('hey', str, lang)
		// if(lang && hljs.getLanguage(lang)) {
		// 	try {
		// 		return `<pre class="hljs"><span class="md-code-lang">${lang}</span><code>${hljs.highlight(lang, str, true).value}</code></pre>`
		// 	} catch (err) { console.log( err) }
		// }

		// return `<pre class="hljs"><span class="md-code-lang">${lang}</span><code>${md.utils.escapeHtml(str)}</code></pre>`
	}
}).use(mde).use(mk).use(mdc).use(prism, { plugins: ['toolbar', 'show-language'] })
