const mk = require('@iktakahiro/markdown-it-katex')
const mde = require('markdown-it-emoji')
const mdc = require('markdown-it-checkbox')
const prism = require('markdown-it-prism')
import './prism-onedark.css'
import 'katex/dist/katex.min.css'

export const md = require('markdown-it')({
	html: true,
	typographer: true,
	langPrefix: 'codeblock language-'
}).use(mde).use(mk).use(mdc).use(prism, { plugins: ['toolbar', 'show-language'] })
