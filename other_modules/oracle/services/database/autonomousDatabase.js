var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token', 'opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDatabases',
                     host : endpoint.service.database[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDatabases/' + 
                            encodeURIComponent(parameters.autonomousDatabaseId),
                     host : endpoint.service.database[auth.region],
                     method : 'DELETE',
                     headers : headers },
                    callback )
};

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDatabases/' + 
                            encodeURIComponent(parameters.autonomousDatabaseId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-response'];
  var possibleQueryStrings = ['compartmentId', 'page', 'limit', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

  ocirest.process( auth, 
                   { path : auth.RESTversion + '/autonomousDatabases' + queryString,
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' }, 
                   callback );
};

function restore( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path: auth.RESTversion + '/autonomousDatabases/' + 
                           encodeURIComponent(parameters.autonomousDatabaseId) + 
                           '/actions/restore',
                     host : endpoint.service.database[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function start( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDatabases/' + 
                            encodeURIComponent(parameters.autonomousDatabaseId) + 
                            '/actions/start',
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'POST' },
                    callback );
};

function stop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDatabases/' + 
                            encodeURIComponent(parameters.autonomousDatabaseId) + 
                            '/actions/stop',
                     headers : headers,
                     host : endpoint.service.database[auth.region],
                     method : 'POST' },
                    callback );
};

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path: auth.RESTversion + '/autonomousDatabases/' + 
                           encodeURIComponent(parameters.autonomousDatabaseId),
                     host : endpoint.service.database[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function generateWallet( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id, opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/autonomousDatabases/' + 
                            encodeURIComponent(parameters.autonomousDatabaseId) + 
                            '/actions/generateWallet',
                     headers : headers,
                     host : endpoint.service.database[auth.region],
                     body : parameters.body,
                     method : 'POST' },
                    callback );
};

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
