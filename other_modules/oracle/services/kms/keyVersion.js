var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/keys' + encodeURIComponent(parameters.keyId) +
                            '/keyVersions',
                     host : endpoint.service.kms[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/keys' + encodeURIComponent(parameters.keyId) +
                            '/keyVersions' + encodeURIComponent(parameters.keyVersionId),
                     host : endpoint.service.kms[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    get: get,
    create: create
    };
