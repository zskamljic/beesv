const path = require('path');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const WasmPackPlugin = require('@wasm-tool/wasm-pack-plugin');

module.exports = {
    mode: process.env.NODE_ENV || 'development',
    entry: {
        bootstrap: './bootstrap.js'
    },
    output: {
        path: path.resolve(__dirname, 'dist/')
    },
    plugins: [
        new WasmPackPlugin({
            crateDirectory: path.resolve(__dirname, 'wallet'),
            outName: 'wallet'
        }),
        new CopyWebpackPlugin({
            patterns: [
                {
                    from: 'static',
                    to: '.'
                }
            ]
        })
    ],
    devtool: 'inline-source-map',
    resolve: {
        extensions: [".js", ".wasm"]
    },
    experiments: {
        asyncWebAssembly: true
    }
}