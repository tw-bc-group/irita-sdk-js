module.exports = {
    target: 'web',
    output: {
        filename: 'web.js'
    },
    // NOTE: https://webpack.js.org/configuration/resolve/#resolvefallback
    resolve: {
        extensions: ['.ts', '.js'],
        fallback: {
          buffer: require.resolve('buffer')
      },
    },
};
