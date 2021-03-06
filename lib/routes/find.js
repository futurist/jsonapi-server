"use strict";
var findRoute = module.exports = { };

var async = require("async");
var helper = require("./helper.js");
var router = require("../router.js");
var postProcess = require("../postProcess.js");
var responseHelper = require("../responseHelper.js");


findRoute.register = function() {
  router.bindRoute({
    verb: "get",
    path: ":type/:id"
  }, function(request, resourceConfig, res) {
    var resource;
    var response;

    async.waterfall([
      function(callback) {
        helper.verifyRequest(request, resourceConfig, res, "find", callback);
      },
      function(callback) {
        request.params.noextra = 1
        resourceConfig.handlers.search(request, callback);
      },
      function(results, pageInfo, meta, callback) {
        if(typeof meta==='function' && !callback) callback = meta, meta=null
        if(meta) responseHelper.setMetadata(meta)
        resource = results[0];
        postProcess.fetchForeignKeys(request, resource, resourceConfig.attributes, callback);
      },
      function(callback) {
        responseHelper._enforceSchemaOnObject(resource, resourceConfig.attributes, callback);
      },
      function(sanitisedData, callback) {
        response = responseHelper._generateResponse(request, resourceConfig, sanitisedData);
        response.included = [ ];
        postProcess.handle(request, response, callback);
      }
    ], function(err) {
      if (err) return helper.handleError(request, res, err);
      return router.sendResponse(res, response, 200);
    });
  });
};
