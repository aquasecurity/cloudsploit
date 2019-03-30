var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
    var possibleHeaders = ['opc-retry-token'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/authTokens/',
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'POST',
                       body : parameters.body },
                      callback )
  };

function drop( auth, parameters, callback ) {
    var possibleHeaders = ['if-match'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/authTokens/' + encodeURIComponent(parameters.authTokenId),
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'DELETE' },
                      callback )
  };

function list( auth, parameters, callback ) {
    var possibleHeaders = [];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/authTokens/',
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

function update( auth, parameters, callback ) {
    var possibleHeaders = ['if-match'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/authTokens/' + encodeURIComponent(parameters.authTokenId),
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       body : parameters.body,
                       method : 'PUT' }, 
                     callback );
  };


  
  module.exports={
      list: list,
      drop: drop,
      update: update,
      create: create
  }