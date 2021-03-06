
module.exports = {
  logIP,
  loginTryCount,
  loginFail,
  loginSuccess,
}

var ms = require('ms')

const MAX_LOGIN_TRY = 10
const BLACKLIST_LOGIN_TIMEOUT = ms('2h')/1e3

var L = require('../../../lang.js')
var _redis = require('redis')
var redis = _redis.createClient({})
redis.on('ready', function () {
  // console.log(redis, Object.keys(redis))
})
redis.on('error', function (err) {
  // console.log(err)
})

function loginSuccess(req, res, next) {
  next = next || function() {}
  if (!redis.ready || !req.fingerprint) return next()
  var key = req.clientIp + '||' + req.fingerprint.hash
  var time = Date.now()
  // reset login try
  redis.hset('login||try', key, 0, function() {})
  next()
}

function loginFail(req, res, next) {
  next = next || function() {}
  if (!redis.ready || !req.fingerprint) return next()
  var key = req.clientIp + '||' + req.fingerprint.hash
  var time = Date.now()
  // increase login try
  redis.hincrby('login||try', key, 1, function (err, val) {
    // console.log(err, val)
    if(err) return next(err)
    // if exceeded the try
    if(val > MAX_LOGIN_TRY) {
      redis.set('blacklist||login||' + key, time, 'ex', BLACKLIST_LOGIN_TIMEOUT, function() {
        redis.hset('login||try', key, 0, function() {})
      })
    } else {
      next()
    }
  })
}

function loginTryCount () {
  return function (req, res, next) {
    // if not ready, ignore this
    if (!redis.ready || !req.fingerprint) return next()
    var key = req.clientIp + '||' + req.fingerprint.hash
    var time = Date.now()
    // if in blacklist ....
    redis.exists('blacklist||login||' + key, function(err, val) {
      if (val) {
        res.status(500).json({message: L('forbidden login', '登录已禁止')})
      } else {
        next()
      }
    })
  }
}

function logIP () {
  return function (req, res, next) {
    if (!redis.ready || !req.fingerprint) return next()
    var key = req.clientIp + '||' + req.fingerprint.hash
    var time = Date.now()

    redis.hset(
      'log||ip||detail',
      time + '||' + key,
      JSON.stringify(req.fingerprint.components),
      function (err) {
        if (err) console.log(err)
      }
    )

    redis.zadd([
      'log||ip',
      time,
      key
    ], function (err, val) {
      if (err) console.log(err)
    })

    next()
  }
}
