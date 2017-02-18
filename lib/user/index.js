module.exports = {
  initLogin,
  initJWT,
  refreshToken
}

var expressJWT = require('express-jwt')
var jwt = require('jsonwebtoken')
var jwtSecret = 'some-united-asia#com.cn'

// handle login
function initLogin(api) {
  return function (req, res) {
    var user = {
      name: req.body.user
    }
    var token = jwt.sign(user, jwtSecret, {expiresIn: ms('7d')/1e3})
    delete lastAction[user.name]
    res.status(200).json({
      token: token,
      user: user
    })
  }
}

function initJWT (api) {
  const base = api._apiConfig.base
  return [
    expressJWT(
      {
        secret: jwtSecret,
        // credentialsRequired: false
      }
    ).unless(function (req) {
      var url = req.url
      return new RegExp('^'+ base +'/(login|person)').test(url)
    }),
    // error middleware
    function (err, req, res, next) {
      if (err.name === 'UnauthorizedError') {
        res.status(401).send('invalid token')
      }
    }
  ]
}

// refresh token middleware
function refreshToken (api) {
  var lastAction = {}
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
      if (last && timestamp - last.timestamp > inactiveTime) {
        return res.status(401).send('invalid token')
      }
      lastAction[user.name] = {
        timestamp,
        url: req.url,
        method: req.method
      }
    }
    next()
  }
}
