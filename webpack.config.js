const HtmlWebpackPlugin = require('html-webpack-plugin')
const MiniCssExtractPlugin = require('mini-css-extract-plugin')
const webpack = require('webpack')

module.exports = {
	devtool: 'source-map',
	watch: true,
	mode: 'development',
	entry: {
		main: './src/index.js'
	},
	output: {
		path: __dirname + '/build/',
		filename: '[name].bundle.js',
        chunkFilename: '[name].bundle.js'
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
            use: [
                MiniCssExtractPlugin.loader,
                'css-loader',
                'sass-loader'
            ]
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
    resolve: {
        alias: {
            "react": "preact/compat",
            "react-dom": "preact/compat"
        }
    },
	plugins: [
		new HtmlWebpackPlugin({
			template: 'src/index.html',
            filename: 'index.html'
		}),
        new MiniCssExtractPlugin({
            filename: 'bundle.css'
        }),
        new webpack.optimize.ModuleConcatenationPlugin()
	]
}
