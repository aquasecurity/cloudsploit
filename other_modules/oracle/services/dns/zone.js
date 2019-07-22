var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/zones' + queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : parameters.body }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['if-none-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/zones/' + encodeURIComponent(parameters.zoneNameOrId) +
                            queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match','if-unmodified-since'];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/zones/' + encodeURIComponent(parameters.zoneNameOrId) + queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'limit', 'page', 'sortBy', 'name', 'nameContains', 'zoneType', 
                              'timeCreatedGreaterThanOrEqualTo', 'timeCreatedLessThan', 'sortOrder', 'lifecycleState'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/zones' + queryString,
                     host : endpoint.service.dns[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    list: list,
    update: update,
    get: get,
    create: create,
    drop: drop
    };
