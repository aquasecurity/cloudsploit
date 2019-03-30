var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/instanceConsoleConnections',
                       host : endpoint.service.core[auth.region],
                       method : 'POST',
                       body : parameters.body,
                       headers : headers },
                      callback )
  };

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                      '/instanceConsoleConnections/' + encodeURIComponent(parameters.instanceConsoleConnectionId),
                       host : endpoint.service.core[auth.region],
                       method : 'DELETE',
                       headers : headers },
                      callback )
  };

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/instanceConsoleConnections/' + encodeURIComponent(parameters.instanceConsoleConnectionId),
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'instanceId', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + '/instanceConsoleConnections' + queryString,
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

  module.exports={
      list: list,
      drop: drop,
      create: create,
      get: get
  }