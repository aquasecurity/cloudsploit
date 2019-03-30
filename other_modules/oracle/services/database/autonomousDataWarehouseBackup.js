var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
var possibleHeaders = ['opc-retry-token'];
var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/autonomousDataWarehouseBackups',
                       host : endpoint.service.database[auth.region],
                       method : 'POST',
                       headers : headers,
                       body : parameters.body }, 
                     callback );
 };

 function get( auth, parameters, callback ) {
    var possibleHeaders = [];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/autonomousDataWarehouseBackups/' + 
                              encodeURIComponent(parameters.autonomousDatabaseBackupId),
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'POST' },
                      callback );
  };

  function list( auth, parameters, callback ) {
    var possibleHeaders = [];
    var possibleQueryStrings = ['autonomousDataWarehouseId', 'compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName' ];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

    ocirest.process( auth,
                     { path : auth.RESTversion + '/autonomousDataWarehouseBackups' + queryString,
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