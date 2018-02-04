<img src="https://avatars0.githubusercontent.com/u/1342004?v=3&s=96" alt="Google Inc. logo" title="Google" align="right" height="96" width="96"/>

# Google OAuth2 JavaScript Client

[![Greenkeeper badge][greenkeeperimg]][greenkeeper]
[![npm version][npmimg]][npm]
[![CircleCI][circle-image]][circle-url]
[![codecov][codecov-image]][codecov-url]
[![Dependencies][david-dm-img]][david-dm]
[![Known Vulnerabilities][snyk-image]][snyk-url]

This is Google's officially supported [node.js][node] client library for using OAuth 2.0 authorization and authentication with Google APIs.

## Installation
This library is distributed on `npm`. To add it as a dependency, run the following command:

``` sh
$ npm install @google/oauth2
```

The [OAuth2][oauth] client that allows you to retrieve an access token and refreshes the token and retry the request seamlessly if you also provide an `expiry_date` and the token is expired. The basics of Google's OAuth2 implementation is explained on [Google Authorization and Authentication documentation][authdocs].

In the following examples, you may need a `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URL`. You can find these pieces of information by going to the [Developer Console][devconsole], clicking your project > APIs & auth > credentials.

For more information about OAuth2 and how it works, [see here][oauth].

#### Using a Proxy
You can use the following environment variables to proxy HTTP and HTTPS requests:

- `HTTP_PROXY` / `http_proxy`
- `HTTPS_PROXY` / `https_proxy`

When HTTP_PROXY / http_proxy are set, they will be used to proxy non-SSL requests that do not have an explicit proxy configuration option present. Similarly, HTTPS_PROXY / https_proxy will be respected for SSL requests that do not have an explicit proxy configuration option. It is valid to define a proxy in one of the environment variables, but then override it for a specific request, using the proxy configuration option.


## License

This library is licensed under Apache 2.0. Full license text is available in [LICENSE][copying].

[authdocs]: https://developers.google.com/accounts/docs/OAuth2Login
[axios]: https://github.com/axios/axios
[axiosOpts]: https://github.com/axios/axios#request-config
[bugs]: https://github.com/JustinBeckwith/google-oauth2-javascript/issues
[circle-image]: https://circleci.com/gh/JustinBeckwith/google-oauth2-javascript.svg?style=svg
[circle-url]: https://circleci.com/gh/JustinBeckwith/google-oauth2-javascript
[codecov-image]: https://codecov.io/gh/JustinBeckwith/google-oauth2-javascript/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/JustinBeckwith/google-oauth2-javascript
[david-dm-img]: https://david-dm.org/JustinBeckwith/google-oauth2-javascript/status.svg
[david-dm]: https://david-dm.org/JustinBeckwith/google-oauth2-javascript
[greenkeeperimg]: https://badges.greenkeeper.io/JustinBeckwith/google-oauth2-javascript.svg
[greenkeeper]: https://greenkeeper.io/
[node]: http://nodejs.org/
[npmimg]: https://img.shields.io/npm/v/@google/oauth2.svg
[npm]: https://www.npmjs.org/package/@google/oauth2
[oauth]: https://developers.google.com/identity/protocols/OAuth2
[snyk-image]: https://snyk.io/test/github/JustinBeckwith/google-oauth2-javascript/badge.svg
[snyk-url]: https://snyk.io/test/github/JustinBeckwith/google-oauth2-javascript
[devconsole]: https://console.developer.google.com
[oauth]: https://developers.google.com/accounts/docs/OAuth2
