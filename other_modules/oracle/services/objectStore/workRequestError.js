var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ){
  var possibleHeaders = ['opc-client-request-id' ];
  var possibleQueryStrings = ['workRequestId', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth,
                     { path : '/workRequests/' + 
                              encodeURIComponent(parameters.workRequestId)+ '/errors' + 
                              queryString,
                       host : endpoint.service.objectStore[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  }

module.exports = {
  list : list
}