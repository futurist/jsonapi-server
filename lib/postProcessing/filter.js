"use strict";
var filter = module.exports = { };

var _ = {
  assign: require("lodash.assign")
};
var debug = require("../debugging.js");
var joi = require("joi");

filter.action = function(request, response, callback) {
  var allFilters = _.assign({ }, request.params.filter);
  if (!allFilters) return callback();

  var filters = { };
  for (var i in allFilters) {
    if (!request.resourceConfig.attributes[i]) {
      return callback({
        status: "403",
        code: "EFORBIDDEN",
        title: "Invalid filter",
        detail: request.resourceConfig.resource + " do not have property " + i
      });
    }
    if (allFilters[i] instanceof Array) {
      allFilters[i] = allFilters[i].join(",");
    }
    if (typeof allFilters[i] === "string") {
      filters[i] = allFilters[i];
    }
  }

  if (response.data instanceof Array) {
    for (var j = 0; j < response.data.length; j++) {
      if (!filter._filterKeepObject(response.data[j], filters, request.resourceConfig.attributes)) {
        debug.filter("removed", filters, JSON.stringify(response.data[j].attributes));
        response.data.splice(j, 1);
        j--;
      }
    }
  } else if (response.data instanceof Object) {
    if (!filter._filterKeepObject(response.data, filters, request.resourceConfig.attributes)) {
      debug.filter("removed", filters, JSON.stringify(response.data.attributes));
      response.data = null;
    }
  }

  return callback();
};

filter._filterMatches = function(textToMatch, propertyText, schema) {
  var castValue=function(v, start){ return joi.attempt(v.substring(start||0), schema) }
  if (textToMatch[0] === ">") {
    var eq = textToMatch[1] === "=";
    textToMatch = eq ? castValue(textToMatch, 2) : castValue(textToMatch, 1);
    if (typeof propertyText === "number") textToMatch = parseInt(textToMatch, 10);
    if (eq? textToMatch <= propertyText : textToMatch < propertyText) return true;
  } else if (textToMatch[0] === "<") {
    var eq = textToMatch[1] === "=";
    textToMatch = eq ? castValue(textToMatch, 2) : castValue(textToMatch, 1);
    if (typeof propertyText === "number") textToMatch = parseInt(textToMatch, 10);
    if (eq ? textToMatch >= propertyText : textToMatch > propertyText ) return true;
  } else if (textToMatch[0] === "~") {
    if ((castValue(textToMatch, 1) + "").toLowerCase() === (propertyText + "").toLowerCase()) return true;
  } else if (textToMatch[0] === ":") {
    if ((propertyText + "").toLowerCase().indexOf((castValue(textToMatch, 1) + "").toLowerCase()) !== -1) return true;
  } else if (castValue(textToMatch,0) === propertyText) return true;
};

filter._filterKeepObject = function(someObject, filters, schema) {
  for (var filterName in filters) {
    var whitelist = filters[filterName].split(",");
    if (someObject.attributes.hasOwnProperty(filterName) || (filterName === "id")) {
      var attributeValue = someObject.attributes[filterName] || "";
      if (filterName === "id") attributeValue = someObject.id;
      var attributeMatches = filter._attributesMatchesOR(attributeValue, whitelist, schema[filterName] );
      if (!attributeMatches) return false;
    } else if (someObject.relationships.hasOwnProperty(filterName)) {
      var relationships = someObject.relationships[filterName] || "";
      var relationshipMatches = filter._relationshipMatchesOR(relationships, whitelist);
      if (!relationshipMatches) return false;
    } else {
      return false;
    }
  }
  return true;
};

filter._attributesMatchesOR = function(attributeValue, whitelist, schema) {
  var matchOR = false;
  whitelist.forEach(function(textToMatch) {
    if (filter._filterMatches(textToMatch, attributeValue, schema)) {
      matchOR = true;
    }
  });
  return matchOR;
};

filter._relationshipMatchesOR = function(relationships, whitelist) {
  var matchOR = false;

  var data = relationships.data;
  if (!data) return false;

  if (!(data instanceof Array)) data = [ data ];
  data = data.map(function(relation) {
    return relation.id;
  });

  whitelist.forEach(function(textToMatch) {
    if (data.indexOf(textToMatch) !== -1) {
      matchOR = true;
    }
  });
  return matchOR;
};
