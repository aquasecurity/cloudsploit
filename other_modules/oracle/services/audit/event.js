var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-client-response'];
  var possibleQueryStrings = ['compartmentId', 'startTime', 'endTime', 'page' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  
  ocirest.process( auth,
                   { path : auth.RESTversion + '/auditEvents' + queryString,
                     host : endpoint.service.audit[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    list: list
    };
