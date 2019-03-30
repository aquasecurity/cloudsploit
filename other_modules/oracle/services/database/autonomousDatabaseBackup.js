var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-response','opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/autonomousDatabaseBackups',
                       host : endpoint.service.database[auth.region],
                       method : 'POST',
                       headers : headers,
                       body : parameters.body }, 
                     callback );
 };

 function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-eresponst-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/autonomousDatabaseBackups/' + 
                              encodeURIComponent(parameters.autonomousDatabaseBackupId),
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'POST' },
                      callback );
  };

  function list( auth, parameters, callback ) {
    var possibleHeaders = ['opc-request-id'];
    var possibleQueryStrings = ['autonomousDatabaseId', 'compartmentId', 'page', 'limit', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName' ];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

    ocirest.process( auth,
                     { path : auth.RESTversion + '/autonomousDatabaseBackups' + queryString,
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'GET' },
                      callback );
  };

  module.exports = {
      get: get,
      create: create,
      list: list
  }