var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
    var possibleHeaders = ['opc-retry-token'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                       '/users/' + encodeURIComponent(parameters.userId) +
                       '/customerSecretKeys/',
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
                       '/customerSecretKeys/' + encodeURIComponent(parameters.customerSecretKeyId),
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'DELETE' },
                      callback )
  };

  module.exports={
      create: create,
      drop: drop
  }