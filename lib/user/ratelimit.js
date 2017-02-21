var RateLimit = require('ratelimit.js').RateLimit
var ExpressMiddleware = require('ratelimit.js').ExpressMiddleware
var redis = require('redis')

var rateLimiter = new RateLimit(
  redis.createClient(),
  [
    // 1min, 600req
    {interval: 1, limit: 10},
    {interval: 60, limit: 600}
  ]
)

var options = {
  ignoreRedisErrors: true
}
var limitMiddleware = new ExpressMiddleware(rateLimiter, options)

function ratelimit() {
  return limitMiddleware.middleware(function(req, res, next) {
    res.status(429).json({message: 'rate limit exceeded'})
  })
}

module.exports = ratelimit
