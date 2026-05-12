module.exports = {
  presets: [
    ['@tarojs/webpack5-runner/appRunner', {}],
    ['@babel/preset-env', { targets: { android: '5.0', ios: '8.0' } }],
    ['@babel/preset-react', {}],
    ['@babel/preset-typescript', {}],
  ],
}
