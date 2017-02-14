'use strict'
var searchRoute = module.exports = { }
var config = require('../config.js')

var async = require('async')
var helper = require('./helper.js')
var router = require('../router.js')
var pagination = require('../pagination.js')
var postProcess = require('../postProcess.js')
var responseHelper = require('../responseHelper.js')

searchRoute.register = function () {
  router.bindRoute({
    verb: 'get',
    path: ':type'
  }, function (request, resourceConfig, res) {
    var searchResults
    var response
    var paginationInfo

    async.waterfall([
      function (callback) {
        helper.verifyRequest(request, resourceConfig, res, 'search', callback)
      },
      function (callback) {
        helper.validate(request.params, resourceConfig.searchParams, callback)
      },
      function validateFilterParams (callback) {
        if (!request.params.filter) return callback()

        for (var i in request.params.filter) {
          if (request.params.filter[i] instanceof Object) continue
          if (!request.resourceConfig.attributes[i]) {
            if(!config.fieldExistsCheck) request.resourceConfig.attributes[i] = {}
            else return callback({
              status: '403',
              code: 'EFORBIDDEN',
              title: 'Invalid filter',
              detail: request.resourceConfig.resource + ' do not have property ' + i
            })
          }
          var relationSettings = request.resourceConfig.attributes[i]._settings
          if (relationSettings && relationSettings.__as) {
            return callback({
              status: '403',
              code: 'EFORBIDDEN',
              title: 'Request validation failed',
              detail: 'Requested relation "' + i + '" is a foreign reference and does not exist on ' + request.params.type
            })
          }
        }

        return callback()
      },
      function validatePaginationParams (callback) {
        pagination.validatePaginationParams(request)
        return callback()
      },
      function (callback) {
        resourceConfig.handlers.search(request, callback)
      },
      function enforcePagination (results, pageInfo, meta, callback) {
        // console.log(pageInfo,meta, 3333)
        if(typeof meta==='function') callback = meta, meta=null
        if(meta) responseHelper.setMetadata(meta)
        searchResults = pagination.enforcePagination(request, results)
        paginationInfo = pageInfo
        return callback()
      },
      function (callback) {
        postProcess.fetchForeignKeys(request, searchResults, resourceConfig.attributes, callback)
      },
      function (callback) {
        const schema = request.base ? resourceConfig._resources[request.base].attributes : resourceConfig.attributes
        responseHelper._enforceSchemaOnArray(searchResults, schema, callback)
      },
      function (sanitisedData, callback) {
        const schema = request.base ? resourceConfig._resources[request.base] : resourceConfig
        response = responseHelper._generateResponse(request, schema, sanitisedData, paginationInfo)
        response.included = [ ]
        postProcess.handle(request, response, callback)
      }
    ], function (err) {
      if (err) return helper.handleError(request, res, err)
      return router.sendResponse(res, response, 200)
    })
  })
}
