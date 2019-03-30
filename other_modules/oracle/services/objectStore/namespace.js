var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
}

function getMetadata( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent( parameters.namespaceName),
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
}

function updateMetadata( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName),
                     host : endpoint.service.objectStore[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

module.exports = {
    get: get,
    getMetadata: getMetadata,
    updateMetadata: updateMetadata
}