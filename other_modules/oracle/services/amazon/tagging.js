var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) + '?tagging',
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'DELETE',
                     headers : headers },
                   callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) + '?tagging',
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'GET',
                     headers : headers },
                   callback );
};

function put( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/' + encodeURIComponent(parameters.bucketName) + '?tagging',
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'PUT',
                     body : parameters.body,
                     headers : headers },
                   callback );
};


module.exports = {
  get: get
  };