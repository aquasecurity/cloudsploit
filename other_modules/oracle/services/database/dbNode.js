var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function action( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token', 'if-match'];
  var possibleQueryStrings = ['action'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbNodes/' +
                            encodeURIComponent( parameters.dbNodeId) + queryString,
                     host : endpoint.service.database[auth.region],
                     method : 'POST',
                     headers: headers },
                   callback );
  };

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbNodes/' + encodeURIComponent(parameters.dbNodeId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
  };

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['dbSystemId', 'compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbNodes' + queryString,
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
  };

module.exports = {
    action: action,
    get: get,
    list: list
}