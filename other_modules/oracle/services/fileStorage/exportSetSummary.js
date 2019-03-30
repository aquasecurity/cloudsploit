var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['availabilityDomain', 'compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName', 'id' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exportSets' + queryString,
                     host : endpoint.service.fileStorage[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list
    };
