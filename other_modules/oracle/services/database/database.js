var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/databases/' + 
                            encodeURIComponent(parameters.databaseId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['dbHomeId', 'compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/databases' + queryString,
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function restore( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                    { path: auth.RESTversion + '/databases/' + 
                            encodeURIComponent(parameters.databaseId) +
                            '/actions/restore',
                     host : endpoint.service.database[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                    { path: auth.RESTversion + '/databases/' + 
                            encodeURIComponent(parameters.databaseId),
                     host : endpoint.service.database[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
};


module.exports = {
    list: list,
    update: update,
    get: get,
    restore: restore
    };
