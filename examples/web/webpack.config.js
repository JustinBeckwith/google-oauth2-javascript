const path = require('path');

module.exports = {
  entry: './build/test/test.oauth2.js',
  output: {
    filename: 'test.oauth2.web.js',
    path: path.resolve(__dirname, 'build/test')
  }
};
