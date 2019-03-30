var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var possibleQueryStrings = ['compartmentId', 'clusterId', 'name', 'limit', 'page', 'sortOrder', 'sortBy'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/nodePools' + queryString,
                     host : endpoint.service.containerEngine[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list
    };
