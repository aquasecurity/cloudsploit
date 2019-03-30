var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function launch( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbSystems',
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
                   { path : auth.RESTversion + '/dbSystems/' + encodeURIComponent(parameters.dbSystemId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
  };

function terminate( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbSystems/' + encodeURIComponent(parameters.dbSystemId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                   callback );
  };
function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbSystems/' + encodeURIComponent(parameters.dbSystemId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'PUT',
                     body : parameters.body },
                   callback );
  };


function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['availabilityDomain', 'backupId', 'compartmentId', 'limit', 
                              'page', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    
    ocirest.process( auth,
                     { path : auth.RESTversion + '/dbSystems' + queryString,
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  };

module.exports = {
    get: get,
    list: list,
    launch: launch,
    terminate: terminate,
    update: update
}