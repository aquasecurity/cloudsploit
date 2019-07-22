var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses',
                     host : endpoint.service.database[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses/' + 
                            encodeURIComponent(parameters.autonomousDataWarehouseId),
                     host : endpoint.service.database[auth.region],
                     method : 'DELETE',
                     headers : headers },
                    callback )
}

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses/' + 
                              encodeURIComponent(parameters.autonomousDataWarehouseId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'page', 'limit', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses/' + queryString,
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function restore( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path: auth.RESTversion + '/autonomousDataWarehouses/' + 
                           encodeURIComponent(parameters.autonomousDataWarehouseId) + 
                           '/actions/restore',
                     host : endpoint.service.database[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function start( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses/' + 
                            encodeURIComponent(parameters.autonomousDataWarehouseId) + 
                            '/actions/start',
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'POST' },
                    callback );
}

function stop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses/' + 
                            encodeURIComponent(parameters.autonomousDataWarehouseId) + 
                            '/actions/stop',
                     headers : headers,
                     host : endpoint.service.database[auth.region],
                     method : 'POST' },
                    callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path: auth.RESTversion + '/autonomousDataWarehouses/' + 
                           encodeURIComponent(parameters.autonomousDataWarehouseId),
                     host : endpoint.service.database[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function generateWallet( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id, opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDataWarehouses/' + 
                            encodeURIComponent(parameters.autonomousDataWarehouseId) + 
                            '/actions/generateWallet',
                     headers : headers,
                     host : endpoint.service.database[auth.region],
                     body : parameters.body,
                     method : 'POST' },
                    callback );
}

module.exports = {
    list: list,
    start: start,
    stop: stop,
    update: update,
    get: get,
    create: create,
    restore: restore,
    drop: drop,
    generateWallet: generateWallet
    };
