'use strict'
var router = module.exports = { }

var _ = {
  assign: require('lodash.assign'),
  omit: require('lodash.omit')
}
var express = require('express')
var app = express()
var server
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser')
var jsonApi = require('./jsonApi.js')
var debug = require('./debugging.js')
var user = require('./user')
var ratelimit = require('./user/ratelimit.js')
var security = require('./user/security.js')
var url = require('url')

// security config
var get_ip = require('ipware')().get_ip
// get client IP
app.use(function (req, res, next) {
  var ip_info = get_ip(req)
  // console.log(ip_info, req.clientIp, req.clientIpRoutable)
  // { clientIp: '127.0.0.1', clientIpRoutable: false }
  next()
})

app.use(function (req, res, next) {
  res.set({
    'Content-Type': 'application/vnd.api+json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || '',
    // "Access-Control-Allow-Headers": "Origin, X-Requested-With, Authorization",
    'Cache-Control': 'private, must-revalidate, max-age=0',
    'Expires': 'Thu, 01 Jan 1970 00:00:00'
  })

  if (req.method === 'OPTIONS') {
    return res.status(204).end()
  }

  return next()
})

app.use(function (req, res, next) {
  if (!req.headers['content-type'] && !req.headers.accept) return next()

  if (req.headers['content-type']) {
    // 415 Unsupported Media Type
    if (req.headers['content-type'].match(/^application\/vnd\.api\+json;.+$/)) {
      return res.status(415).end()
    }

    // Convert "application/vnd.api+json" content type to "application/json".
    // This enables the express body parser to correctly parse the JSON payload.
    if (req.headers['content-type'].match(/^application\/vnd\.api\+json$/)) {
      req.headers['content-type'] = 'application/json'
    }
  }

  if (req.headers.accept) {
    // 406 Not Acceptable
    var matchingTypes = req.headers.accept.split(/, ?/)
    matchingTypes = matchingTypes.filter(function (mediaType) {
      // Accept application/*, */vnd.api+json, */* and the correct JSON:API type.
      return mediaType.match(/^(\*|application)\/(\*|vnd\.api\+json)$/) || mediaType.match(/\*\/\*/)
    })

    if (matchingTypes.length === 0) {
      return res.status(406).end()
    }
  }

  return next()
})


// rate limit
app.use(ratelimit())
app.use(user.initFingerPrint(jsonApi))
app.use(security.logIP())

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())

router.setupAuth = function () {
  app.post('/login', security.loginTryCount(), user.initLogin(jsonApi))
  app.patch('/login', user.initChangePass(jsonApi))
  app.use(
    // path
    jsonApi._apiConfig.base,
    // middleware
    user.initJWT(jsonApi),
    user.checkToken(jsonApi),
    user.checkFingerPrint(jsonApi)
  )
}

app.disable('x-powered-by')
app.disable('etag')

var requestId = 0
app.route('*').all(function (req, res, next) {
  debug.requestCounter(requestId++, req.method, req.url)
  if (requestId > 1000) requestId = 0
  next()
})

router.listen = function (port) {
  if (!server) {
    server = app.listen(port)
  }
}

router.close = function () {
  if (server) {
    server.close()
    server = null
  }
}

router.bindRoute = function (config, callback) {
  app[config.verb](jsonApi._apiConfig.base + config.path, function (req, res) {
    // add: inherited
    var request = router._getParams(req)
    var type = request.params.type
    var typeForm = jsonApi._formtype[type]
    var inherited = typeForm && typeForm.inherited
    if (inherited) {
      inherited = 'form_' + inherited
      var inheritedForm = jsonApi._formtype[inherited]
      request.params.type = inherited
      request.params.noextra = 1
      request.inherited = type
    }
    var colName = inherited || type
    var resourceConfig = jsonApi._resources[colName]
    // console.log(resourceConfig, type, inherited, 3333)

    router._setResponseHeaders(request, res)
    request.resourceConfig = resourceConfig
    router.authenticate(request, res, function () {
      return callback(request, resourceConfig, res)
    })
  })
}

router.authenticate = function (request, res, callback) {
  if (!router._authFunction) return callback()

  router._authFunction(request, function (err) {
    if (!err) return callback()

    res.status(401).end()
  })
}

router.authenticateWith = function (authFunction) {
  router._authFunction = authFunction
}

router.bind404 = function (callback) {
  app.use(function (req, res) {
    var request = router._getParams(req)
    router._setResponseHeaders(request, res)
    return callback(request, res)
  })
}

router.bindErrorHandler = function (callback) {
  app.use(function (error, req, res, next) {
    var request = router._getParams(req)
    router._setResponseHeaders(request, res)
    return callback(request, res, error, next)
  })
}

router._getParams = function (req) {
  var urlParts = req.url.split(jsonApi._apiConfig.base)
  urlParts.shift()
  urlParts = urlParts.join(jsonApi._apiConfig.base).split('?')

  var headersToRemove = [
    'host', 'connection', 'accept-encoding', 'accept-language', 'content-length'
  ]

  var combined, reqUrl = req.url
  if (jsonApi._apiConfig.urlPrefixAlias) {
    combined = jsonApi._apiConfig.urlPrefixAlias.replace(/\/$/, '')
	  reqUrl = reqUrl.replace(jsonApi._apiConfig.base, '/')
  } else {
    combined = url.format({
      protocol: jsonApi._apiConfig.protocol,
      hostname: jsonApi._apiConfig.hostname,
      port: jsonApi._apiConfig.port
    })
  }

  combined += reqUrl

  Object.keys(req.query).forEach(function (v) {
    if (typeof req.query[v] === 'object') req.query[v] = removeNumericKeys(req.query[v])
  })

  return {
    // JWT
    user: req.user,
    clientIp: req.clientIp,
    fingerprint: req.fingerprint,
    params: _.assign(req.params, req.body, req.query),
    headers: req.headers,
    safeHeaders: _.omit(req.headers, headersToRemove),
    cookies: req.cookies,
    route: {
      verb: req.method,
      host: req.headers.host,
      base: jsonApi._apiConfig.base,
      path: urlParts.shift() || '',
      query: urlParts.shift() || '',
      combined: combined
    }
  }
}

router._setResponseHeaders = function (request, res) {
  res.set({
    'Content-Type': 'application/vnd.api+json',
    'Location': request.route.combined,
    'Access-Control-Expose-Headers': 'client-hash',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': '*'
  })
}

router.sendResponse = function (res, payload, httpCode) {
  res.status(httpCode).json(payload)
}

/**
 * String object will have numeric keys, remove it
 * @param {} obj
 * @returns {} newObj
 */
function removeNumericKeys (obj) {
  var newObj = {}
  Object.keys(obj).forEach(function (v) {
    if (isNaN(Number(v))) newObj[v] = obj[v]
  })
  return newObj
}
