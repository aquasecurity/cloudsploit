var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
    var possibleHeaders = ['opc-retry-token'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/swiftPasswords/',
                       host : endpoint.service.iam[auth.region],
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
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/swiftPasswords/' + encodeURIComponent(parameters.swiftPasswordId),
                       host : endpoint.service.iam[auth.region],
                       method : 'DELETE',
                       headers : headers },
                      callback )
  };

function list( auth, parameters, callback ) {
    var possibleHeaders = [];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/swiftPasswords/',
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
                              '/swiftPasswords/' + encodeURIComponent(parameters.swiftPasswordId),
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