var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function put( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/l',
                     host : endpoint.service.objectStore[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/l',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/l',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

module.exports = {
    get: get,
    put: put,
    drop: drop
    };
