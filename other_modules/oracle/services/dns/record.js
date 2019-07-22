var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function updateDomain( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function updateZone( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records' + queryString,
                     host : endpoint.service.dns[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}


function getDomain( auth, parameters, callback ) {
  var possibleHeaders = ['if-none-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'zoneVersion', 'rType'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent( parameters.domain) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function getZone( auth, parameters, callback ) {
  var possibleHeaders = ['if-none-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'zoneVersion', 'rType', 'domain', 'domainContains'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records' + queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}


function patchDomain( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) + 
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     body: parameters.body,
                     method : 'PATCH' },
                    callback );
}

function patchZone( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records' + queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     body: parameters.body,
                     method : 'PATCH' },
                    callback );
}


function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            '/records/' + encodeURIComponent(parameters.domain) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
}

module.exports = {
    updateDomain: updateDomain,
    updateZone: updateZone,
    getDomain: getDomain,
    getZone: getZone,
    patchDomain: patchDomain,
    patchZone: patchZone,
    drop: drop
    };
