var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) +
                            '/' + encodeURIComponent(parameters.rtype) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = ['if-none-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId','limit','page','zoneVersion'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) +
                            '/' + encodeURIComponent(parameters.rtype) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function patch( auth, parameters, callback ) {
  var possibleHeaders = ['if-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) +
                            '/' + encodeURIComponent(parameters.rtype) + 
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     body: parameters.body,
                     method : 'PATCH' },
                    callback );
};


function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) +
                            '/' + encodeURIComponent(parameters.rtype) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

module.exports = {
    update: update,
    get: get,
    patch: patch,
    drop: drop
    };
