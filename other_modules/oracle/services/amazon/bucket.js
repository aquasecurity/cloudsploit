var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'DELETE',
                     headers : headers },
                   callback );
}

function head( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'HEAD',
                     headers : headers },
                   callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var possibleQueryStrings = ['delimeter', 'encoding-type', 'max-keys', 'prefix', 'continuation-token', 'start-after'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) + queryString,
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'GET',
                     headers : headers },
                   callback );
}

function put( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'PUT',
                     headers : headers },
                   callback );
}

module.exports = {
  drop: drop,
  head: head,
  list: list,
  put: put
  };