var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function cancel( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : '/workRequests/' + encodeURIComponent(parameters.workRequestId),
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'DELETE' },
                     callback );
  }

function get( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : '/workRequests/' + encodeURIComponent(parameters.workRequestId),
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  }

function list( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id' ];
  var possibleQueryStrings = ['compartmentId', 'workRequestType', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth,
                     { path : '/workRequests' + queryString,
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  }

module.exports = {
  cancel : cancel,
  get : get,
  list : list
}