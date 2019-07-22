var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/workRequests/' + encodeURIComponent(parameters.workRequestId),
                     host : endpoint.service.containerEngine[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match', 'opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/workRequests/' + encodeURIComponent(parameters.workRequestId),
                     host : endpoint.service.containerEngine[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
}

module.exports = {
    get: get,
    drop: drop
    };
