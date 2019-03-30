var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/images',
                       host : endpoint.service.core[auth.region],
                       method : 'POST',
                       body : parameters.body,
                       headers : headers },
                      callback )
  };

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                      '/images/' + encodeURIComponent(parameters.imageId),
                       host : endpoint.service.core[auth.region],
                       method : 'DELETE',
                       headers : head },
                      callback )
  };

function exportImage( auth, parameters, callback ) {
  var possibleHeaders = ['if-match','opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/images/' + encodeURIComponent(parameters.imageId) +
                              '/actions/export',
                       host : endpoint.service.core[auth.region],
                       method : 'POST',
                       body : parameters.body,
                       headers : headers },
                      callback )
  };

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/images/' + encodeURIComponent(parameters.imageId),
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'displayName', 'operatingSystem', 'operatingSystemVersion', 
                              'shape', 'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + '/images' + queryString,
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

function update( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + '/images/' + encodeURIComponent(parameters.imageId),
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       body : parameters.body,
                       method : 'PUT' }, 
                     callback );
  };
  
  module.exports={
      list: list,
      drop: drop,
      update: update,
      create: create,
      get: get,
      exportImage: exportImage
  }