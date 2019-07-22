var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'emailAddress', 'limit', 'page', 'sortBy', 'sortOrder', 
                              'itimeCreatedGreaterThanOrEqualTo', 'timeCreatedLessThan' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/suppressions' + queryString,
                     host : endpoint.service.email[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}
module.exports = {
    list: list
    };
