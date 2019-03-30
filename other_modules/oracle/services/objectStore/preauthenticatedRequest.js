var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                              '/b/' + encodeURIComponent(parameters.bucketName) +
                              '/p/',
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'POST',
                       body : parameters.body },
                     callback );
  }

function drop( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                              '/b/' + encodeURIComponent(parameters.bucketName) +
                              '/p/' + encodeURIComponent(parameters.parId),
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'DELETE' },
                     callback );
  }

function get( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                              '/b/' + encodeURIComponent(parameters.bucketName) +
                              '/p/' + encodeURIComponent(parameters.parId),
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  }

function list( auth, parameters, callback ){
  var possibleHeaders = [];
  var possibleQueryStrings = ['objectName', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth,
                     { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                              '/b/' + encodeURIComponent(parameters.bucketName) +
                              '/p/' + queryString,
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  }

module.exports = {
  create : create,
  drop : drop,
  get : get,
  list : list
}