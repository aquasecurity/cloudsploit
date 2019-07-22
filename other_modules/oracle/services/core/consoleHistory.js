var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function capture( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/instanceConsoleHistories/',
                       host : endpoint.service.core[auth.region],
                       method : 'POST',
                       body : parameters.body,
                       headers : headers },
                      callback )
  }

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                      '/instanceConsoleHistories/' + encodeURIComponent(parameters.instanceConsoleHistoryId),
                       host : endpoint.service.core[auth.region],
                       method : 'DELETE',
                       headers : headers },
                      callback )
  }

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/instanceConsoleHistories/' + encodeURIComponent(parameters.instanceConsoleHistoryId),
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  }

function getContent( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['offset', 'length' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/instanceConsoleHistories/' + encodeURIComponent(parameters.instanceConsoleHistoryId) +
                              '/data' + queryString,
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  }


function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'availabilityDomain', 'limit', 'page', 'instanceId', 'sortBy', 'sortOrder', 'lifecycleState' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                      '/instanceConsoleHistories/' + encodeURIComponent(parameters.instanceConsoleHistoryId) + queryString,
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  }

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/instanceConsoleHistories/' + encodeURIComponent(parameters.instanceConsoleHistoryId),
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       body : parameters.body,
                       method : 'PUT' }, 
                     callback );
  }
  
  module.exports={
      list: list,
      drop: drop,
      update: update,
      capture: capture,
      getContent: getContent,
      get: get
  }