var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function abortMultipartUpload( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var possibleQueryStrings = ['uploadId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/u/' + encodeURIComponent(parameters.objectName) +
                            queryString,
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                   callback );
}

function commitMultipartUpload( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none'];
  var possibleQueryStrings = ['uploadId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
   ocirest.process( auth,
     { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
              '/b/' + encodeURIComponent(parameters.bucketName) + 
              '/u/' + encodeURIComponent(parameters.objectName) + 
              queryString,
       host : endpoint.service.objectStore[auth.region],
       headers : headers,
       method : 'POST',
       body : parameters.body },
     callback );  
}

function copy( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
    { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
             '/b/' + encodeURIComponent(parameters.bucketName) + 
             '/actions/copyObject',
      host : endpoint.service.objectStore[auth.region],
      headers : headers,
      body : parameters.body,
      method : 'POST' },
    callback ); 
}

function createMultipartUpload( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
    { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
             '/b/' + encodeURIComponent(parameters.bucketName) + 
             '/u',
      host : endpoint.service.objectStore[auth.region],
      headers : headers,
      body : parameters.body,
      method : 'POST' },
    callback );
}

function drop( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/o/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                   callback );
}

function get( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none', 'range'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) +
                            '/o/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
}

function head( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) +
                            '/o/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'HEAD' },
                   callback );
}

function listMultipartUploadParts( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var possibleQueryStrings = ['uploadId', 'page', 'limit'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/u/' + encodeURIComponent(parameters.objectName) +
                             queryString,
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
}

function listMultipartUploads( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var possibleQueryStrings = ['page', 'limit'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/u' + queryString,
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
}


function list( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var possibleQueryStrings = ['prefix', 'start', 'end', 'limit', 'delimiter', 'fields'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/o' + queryString,
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
}


function put( auth, parameters, callback ){
  //var fs = require('fs');
  //var buffer = fs.readFileSync(parameters.fileName);
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none', 'expect',
                         'content-length', 'content-MD5', 'content-type', 'content-language',
                         'content-encoding' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters, true );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/o/' + encodeURIComponent(parameters.objectName),
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     body : parameters.body,
                     method : 'PUT' },
                   callback ); 
}

function rename( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/actions/renameObject',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : parameters.body },
                   callback );
}

function restore( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
                            '/b/' + encodeURIComponent(parameters.bucketName) + 
                            '/actions/restoreObjects',
                     host : endpoint.service.objectStore[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : parameters.body },
                   callback );
}


function uploadPart( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-request-id', 'if-match', 'if-match-none', 'expect',
                         'content-length', 'content-MD5'];
  var possibleQueryStrings = ['uploadId', 'uploadPartNum'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters, true );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
    { path : '/n/' + encodeURIComponent(parameters.namespaceName) + 
             '/b/' + encodeURIComponent(parameters.bucketName) + 
             '/u/' + encodeURIComponent(parameters.objectName) + 
             queryString,
      host : endpoint.service.objectStore[auth.region],
      headers : headers,
      method : 'PUT',
      body : parameters.body },
      callback );
}


module.exports = {
    abortMultipartUpload: abortMultipartUpload,
    commitMultipartUpload: commitMultipartUpload,
    copy : copy,
    createMultipartUpload: createMultipartUpload,
    drop: drop,
    get: get,
    head: head,
    listMultipartUploadParts : listMultipartUploadParts,
    listMultipartUploads : listMultipartUploads,
    list: list,
    put: put,
    rename: rename,
    restore: restore,
    uploadPart: uploadPart
}