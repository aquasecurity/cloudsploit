var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function drop( auth, parameters, callback ) {
    var possibleHeaders = ['if-match'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/apiKeys/' + encodeURIComponent(parameters.fingerprint),
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
                              '/apiKeys/',
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

function upload( auth, parameters, callback ) {
    var possibleHeaders = ['opc-retry-token'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/users/' + encodeURIComponent(parameters.userId) +
                              '/apiKeys/',
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       body : parameters.body,
                       method : 'POST' }, 
                     callback );
  };


  
  module.exports={
      list: list,
      drop: drop,
      upload: upload
  }