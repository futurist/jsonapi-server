"use strict";
var assert = require("assert");
var helpers = require("./helpers.js");
var jsonApiTestServer = require("../example/server.js");


describe("Testing jsonapi-server", function() {
  describe("Finding a related resource", function() {
    it("unknown id should error", function(done) {
      var url = "http://localhost:16006/rest/articles/foobar/author";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateError(json);
        assert.equal(res.statusCode, "404", "Expecting 404");

        done();
      });
    });

    it("unknown relation should error", function(done) {
      var url = "http://localhost:16006/rest/articles/de305d54-75b4-431b-adb2-eb6b9e546014/foobar";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateError(json);
        assert.equal(res.statusCode, "404", "Expecting 404");

        done();
      });
    });

    it("foreign relation should error", function(done) {
      var url = "http://localhost:16006/rest/people/cc5cca2e-0dd8-4b95-8cfc-a11230e73116/articles";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateError(json);
        assert.equal(json.errors[0].code, "EFOREIGN");
        assert.equal(res.statusCode, "404", "Expecting 404");

        done();
      });
    });

    it("Lookup by id", function(done) {
      var url = "http://localhost:16006/rest/articles/de305d54-75b4-431b-adb2-eb6b9e546014/author";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateJson(json);

        assert.equal(res.statusCode, "200", "Expecting 200 OK");
        helpers.validateResource(json.data);
        assert.equal(json.data.type, "people", "Should be a people resource");

        done();
      });
    });

    it("with fields", function(done) {
      var url = "http://localhost:16006/rest/articles/de305d54-75b4-431b-adb2-eb6b9e546014/author?fields[people]=email";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateJson(json);

        assert.equal(res.statusCode, "200", "Expecting 200 OK");
        helpers.validateResource(json.data);
        var keys = Object.keys(json.data.attributes);
        assert.deepEqual(keys, [ "email" ], "Should only contain email attribute");

        done();
      });
    });

    xit("with filter", function(done) {
      var url = "http://localhost:16006/rest/articles/de305d54-75b4-431b-adb2-eb6b9e546014/author?filter[email]=email";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateJson(json);

        assert.equal(res.statusCode, "200", "Expecting 200 OK");
        assert.deepEqual(json.data, null);

        done();
      });
    });

    it("[futurist] with filter", function(done) {
      var email = encodeURIComponent('oliver.rumbelow@example.com')
      var url = "http://localhost:16006/rest/articles/de305d54-75b4-431b-adb2-eb6b9e546014/author?filter[email]="+email;
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateJson(json);

        assert.equal(res.statusCode, "200", "Expecting 200 OK");
        // assert.deepEqual(json.data, null);
        // it's have to validate with email, or throw error
        assert.deepEqual(json.data.id, 'cc5cca2e-0dd8-4b95-8cfc-a11230e73116')

        done();
      });
    })

    it("with includes", function(done) {
      var url = "http://localhost:16006/rest/articles/de305d54-75b4-431b-adb2-eb6b9e546014/author?include=articles";
      helpers.request({
        method: "GET",
        url: url
      }, function(err, res, json) {
        assert.equal(err, null);
        json = helpers.validateJson(json);

        assert.equal(res.statusCode, "200", "Expecting 200 OK");
        assert.equal(json.included.length, 1, "Should be 1 included resource");

        var people = json.included.filter(function(resource) {
          return resource.type === "articles";
        });
        assert.equal(people.length, 1, "Should be 1 included articles resource");

        done();
      });
    });
  });

  before(function() {
    jsonApiTestServer.start();
  });
  after(function() {
    jsonApiTestServer.close();
  });
});
