var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-re'];
  var possibleQueryStrings = ['compartmentId', 'limit', 'page', 'soryBy', 'sortOrder'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

  ocirest.process( auth,
                   { path : auth.RESTversion + '/keys/' + encodeURIComponent(parameters.keyId) +
                            '/keyVersions' + queryString,
                     host : endpoint.service.kms[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    list: list
    };
