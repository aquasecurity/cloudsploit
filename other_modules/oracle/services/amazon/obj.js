var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function abortMultipartUpload( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['uploadId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName) +
                            queryString,
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'DELETE',
                     headers : headers },
                   callback );
}

function completeMultipartUpload( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['uploadId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName) +
                            queryString,
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'POST',
                     body : parameters.body,
                     headers : headers },
                   callback );
}


function drop( auth, parameters, callback ) {
  var possibleHeaders = ['If-Match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'DELETE',
                     headers : headers },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['If-Match', 'If-None-Match', 'If-Modified-Since', 'If-Unmodified-Since', 'range', 'x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'GET',
                     headers : headers },
                   callback );
}

function head( auth, parameters, callback ) {
  var possibleHeaders = ['If-Match', 'If-None-Match', 'If-Modified-Since', 'If-Unmodified-Since', 'range', 'x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'HEAD',
                     headers : headers },
                   callback );
}

function initiateMultipartUpload( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName) +
                            '?uploads',
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'POST',
                     headers : headers },
                   callback );
}

function listParts( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['uploadId', 'max-parts', 'part-number-marker', 'encoding-type', ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName) +
                            queryString,
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'GET',
                     headers : headers },
                   callback );
}

function listUploads( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['max-uploads', 'key-marker', 'upload-marker-id', 'encoding-type', ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '?uploads' + 
                            (queryString=='' ? '' : '&' + queryString.replace('?','')),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'GET',
                     headers : headers },
                   callback );
}

function put( auth, parameters, callback ) {
  var possibleHeaders = ['Expect', 'Content-Length', 'Content-MD5', 'Content-Type', 'Content-Encoding'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'PUT',
                     body : body,
                     uploadFile : true,
                     headers : headers },
                   callback );
}

function restoreObjects( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName) +
                            '?restore',
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'POST',
                     body : body,
                     headers : headers },
                   callback );
}

function uploadPart( auth, parameters, callback ) {
  var possibleQueryStrings = ['upload-Id'];
  var possibleHeaders = ['Expect', 'Content-Length', 'Content-MD5', 'Content-Type'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) +
                            '/' + encodeURIComponent(parameters.objectName) +
                            queryString,
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'PUT',
                     body : body,
                     uploadFile : true,
                     headers : headers },
                   callback );
}


module.exports = {
  abortMultipartUpload: abortMultipartUpload,
  completeMultipartUpload: completeMultipartUpload,
  drop: drop,
  get: get,
  head: head,
  initiateMultipartUpload: initiateMultipartUpload,
  listParts: listParts,
  listUploads: listUploads,
  put: put,
  restoreObjects: restoreObjects,
  uploadPart: uploadPart 
};