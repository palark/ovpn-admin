const path = require('path');
const webpack = require('webpack');

const isDevelopment = process.env.NODE_ENV === 'development';

module.exports = {
    mode: isDevelopment ? 'development' : 'production',
    devtool: isDevelopment ? 'eval-cheap-module-source-map' : false,
    entry: {
      bundle: [
        './src/main.js',
      ],
      style: [
        './src/style.js',
      ]
    },
    output: {
      path: path.resolve(__dirname, './static/dist'),
      publicPath: '/dist/',
      filename: '[name].min.js'
    },
    plugins: [
      // Feature flags of the Vue esm-bundler build:
      // https://vuejs.org/api/compile-time-flags.html
      new webpack.DefinePlugin({
        __VUE_OPTIONS_API__: JSON.stringify(true),
        __VUE_PROD_DEVTOOLS__: JSON.stringify(false),
        __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: JSON.stringify(false),
      }),
    ],
    module: {
      rules: [
        {
          test: /\.css$/,
          use: [
            'style-loader',
            'css-loader'
          ],
        },
        {
          // babel options live in .babelrc
          test: /\.js$/,
          exclude: /node_modules/,
          loader: 'babel-loader',
        },
      ],
    },
    resolve: {
      alias: {
        // templates live in static/index.html and are compiled at runtime,
        // so the build that includes the template compiler is required
        'vue$': 'vue/dist/vue.esm-bundler.js',
      },
      extensions: ['.js', '.json']
    },
    performance: {
      // single-page admin UI embedded into the Go binary: the bundles are
      // expected to be bigger than the 244 KiB default (CSS is inlined into
      // style.min.js by style-loader), there is nothing to split
      maxAssetSize: 1024 * 1024,
      maxEntrypointSize: 1024 * 1024,
    },
    devServer: {
      // index.html and favicon.ico are served from static/,
      // bundles are served from memory under output.publicPath (/dist/)
      static: {
        directory: path.resolve(__dirname, 'static'),
      },
      hot: true,
      // API requests go to a running ovpn-admin instance
      proxy: [
        {
          context: ['/api'],
          target: process.env.OVPN_ADMIN_URL || 'http://127.0.0.1:8080',
        },
      ],
    },
  }
