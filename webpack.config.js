const path = require('path')
const HtmlWebpackPlugin = require('html-webpack-plugin')
const ExtractTextPlugin = require('extract-text-webpack-plugin')

var extractPlugin = new ExtractTextPlugin({
	filename: 'main.css'
})

module.exports = {
	devtool: 'source-map',
	watch: true,
	mode: 'development',
	entry: {
		sua: './src/util/su-analytics.js',
		bundle: './src/index.js'
	},
	node: {
		fs: 'empty',
		net: 'empty',
		tls: 'empty'
	},
	output: {
		path: path.resolve(__dirname, 'build'),
		filename: '[name].js',
		publicPath: './',
	},
	module: {
		rules: [{
			test: /\.jsx?$/,
			exclude: /node_modules/,
			loader: 'babel-loader',
			options: {
				presets: ['@babel/preset-env', '@babel/react']
			}
		},
		{
			test: /\.(sa|c)ss$/,
			use: extractPlugin.extract({
				use: ['css-loader', 'sass-loader']
			})
		},
		{
			test: /\.(png|jpe?g|gif|svg|eot|svg|otf|ttf|woff|woff2|md)$/,
			loader: 'file-loader',
			options: {
				name: 'assets/[name].[ext]'
			}
		},
		{
			test: /\.html$/,
			use: ['html-loader']
		},
		// {
		// 	test: /\.md$/,
		// 	use: ['json-loader', 'yaml-frontmatter-loader']
		// }
		]
	},
	plugins: [
		extractPlugin,
		new HtmlWebpackPlugin({
			template: 'src/index.html'
		})
	]
}