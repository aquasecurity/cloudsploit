var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/',
                     host : endpoint.service.objectStore[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + '/',
                     host : endpoint.service.objectStore[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + '/',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function head( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + '/',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'HEAD' },
                    callback );
};

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + '/',
                     host : endpoint.service.objectStore[auth.region],
                     method : 'DELETE' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id' ];
  var possibleQueryStrings = ['compartmentId', 'fields', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/n/' +  encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + queryString,
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    update: update,
    get: get,
    create: create,
    head: head,
    drop: drop
    };
