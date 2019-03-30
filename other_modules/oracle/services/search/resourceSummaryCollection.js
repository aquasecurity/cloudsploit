var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function search( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var possibleQueryStrings = ['limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/resources' + queryString,
                     host : endpoint.service.search[auth.region],
                     headers : headers,
                     body : parameters.body,
                     method : 'POST' },
                    callback );
};

module.exports = {
    search: search
    };
