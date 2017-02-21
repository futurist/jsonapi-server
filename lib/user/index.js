module.exports = {
  lastAction,
  initFingerPrint,
  initChangePass,
  initLogin,
  initJWT,
  checkToken,
  checkFingerPrint
}

var ms = require('ms')
var Fingerprint = require('express-fingerprint')
var expressJWT = require('express-jwt')
var jwt = require('jsonwebtoken')
var jwtSecret = 'some-united-asia#com.cn'
var L = require('../../../lang.js')

// global
var lastAction = {}
var lastLogin = {}

function initFingerPrint(api) {
  // SET req.fingerprint
  return [
    Fingerprint({
      parameters: [
        // Defaults
        Fingerprint.useragent,
        // Fingerprint.acceptHeaders,
        Fingerprint.geoip,

        // Additional parameters
        function(next) {
          const agent = this.req.headers['user-agent']
          next(null,{
            slogan: jwtSecret,
            agent: agent
          })
        },
      ]
    })
  ]
}

// handle login
function _loginSuccess (req, res) {
  var user = {
    name: req.body.user
  }
  var token = jwt.sign(user, jwtSecret, {expiresIn: ms('7d') / 1e3})
  lastAction[user.name] = {
    hash: req.body.hash
  }
  res.status(200).json({
    token: token,
    user: user
  })
}

function initChangePass (api) {
  return function(req, res) {
    var user = {
      name: req.body.user,
      pass: req.body.pass,
      newPass: req.body.newPass,
    }
    api.changePass(user, function(err, result) {
      // console.log(err, result, 3333333)
      if(err || !result) res.status(500).json({message: err.message})
      else res.status(200).json(L('successful change pass', '修改密码成功'))
    })
  }
}

function initLogin (api) {
  return function(req, res) {
    var user = {
      name: req.body.user,
      pass: req.body.pass,
    }

    var last = lastLogin[user.name] = lastLogin[user.name] || {}
    if (last && new Date() - last.time < 1e3) {
      last.time = new Date()
      return res.status(500).json(
        {message: L('too fast login, try 5 sec later', '登录过快, 5秒后重试')}
      )
    }
    if (last && new Date() - last.time < 1e3) {
      last.time = new Date()
      return res.status(500).json(
        {message: L('too fast login, try 5 sec later', '登录过快, 5秒后重试')}
      )
    }
    const lastTime = last.time = new Date()
    last.ip = req.clientIp
    last.count = last.count||0
    last.count++

    api.authUser(user, function(err, result) {
      // console.log(err, result, 3333333)
      if(err || !result) res.status(500).json(
        {message: err && err.message || L('invalid user/pass', '错误的用户或密码')}
      )
      else _loginSuccess(req, res)
    })
  }
}

function initJWT (api) {
  const base = api._apiConfig.base
  return [
    // SET req.user
    expressJWT(
      {
        secret: jwtSecret
        // credentialsRequired: false
      }
    ).unless(function (req) {
      var url = req.url
      return new RegExp('^' + base + '/(login|person)').test(url)
    }),
    // error middleware
    function (err, req, res, next) {
      if (err.name === 'UnauthorizedError') {
        res.status(401).send(L('invalid token'))
      }
    }
  ]
}

// refresh token middleware
function checkToken (api) {
  return function (req, res, next) {
    // console.log(Object.keys(req), req.secret, req.user,  333)
    // req.user: {name: xxx, iat: 1487208572, exp: 1487209472}
    var timestamp = Math.floor(Date.now() / 1000)
    var user = req.user
    if (user) {
      // Method 1. half exp passed, auto renew token
      let checkpoint = (user.exp - user.iat) / 2 + user.iat
      // console.log(last, checkpoint, 333)
      if (timestamp > checkpoint) {
        // res.set('x-refresh-token', 'new token')
      }
      // Method 2. check last timestamp, and force login
      const last = lastAction[user.name]
      const inactiveTime = ms('8h') / 1e3  // 8 hours
      if (!last) {
        return res.status(401).send('invalid last')
      }
      if (timestamp - last.timestamp > inactiveTime) {
        return res.status(401).send('token timeout')
      }
      last.timestamp = timestamp
      last.url = req.url
      last.method = req.method
      // json-api will drop req.user, save it to headers
      req.headers.user = req.user
    }
    next()
  }
}

function checkFingerPrint(api) {
  return function(req, res, next) {
    // console.log(req.fingerprint, req.user, lastAction, 333)
    if(req.fingerprint && req.user && lastAction) {
      const last = lastAction[req.user.name]
      if (last.serverFP && last.serverFP != req.fingerprint.hash) {
        return res.status(401).send('invalid request')
      }
      last.serverFP = req.fingerprint.hash
      res.set({
        'client-hash': last.hash
      })
      // json-api will drop req.clientHash, save it into headers
      req.headers.clientHash = last.hash
    }
    next()
  }
}
