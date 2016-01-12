"use strict";
var fields = module.exports = { };

var jsonApi = require("../jsonApi.js");

fields.action = function(request, response, callback) {
  var resourceList = request.params.fields;
  if (!resourceList || !(resourceList instanceof Object)) return callback();

  var allDataItems = response.included.concat(response.data);
  var fieldsMap = {}
  for (var resource in resourceList) {
    if (!jsonApi._resources[resource]) {
      return callback({
        status: "403",
        code: "EFORBIDDEN",
        title: "Invalid field resource",
        detail: resource + " is not a valid resource "
      });
    }

    var field = ("" + resourceList[resource]).split(",");
    fieldsMap[resource] = field;

    for (var i = 0; i < field.length; i++) {
      var j = field[i];
      if (!jsonApi._resources[resource].attributes[j]) {
        return callback({
          status: "403",
          code: "EFORBIDDEN",
          title: "Invalid field selection",
          detail: resource + " do not have property " + j
        });
      }
    }
  }


  allDataItems.forEach(function(dataItem) {
    Object.keys(dataItem.attributes).forEach(function(attribute) {
      if (fieldsMap[dataItem.type] && fieldsMap[dataItem.type].indexOf(attribute) === -1) {
        delete dataItem.attributes[attribute];
      }
    });
  });

  return callback();
};
