var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['exportSetId', 'fileSystemId', 'id', 'compartmentId', 
                              'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exports' + queryString,
                     host : endpoint.service.fileStorage[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    list: list
    };
