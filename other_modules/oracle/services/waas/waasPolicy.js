var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
    var possibleHeaders = ['opc-request-id'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
        { path : auth.RESTversion +
                '/waasPolicies/' + encodeURIComponent(parameters.waasPolicyId),
            host : endpoint.service.waas[auth.region],
            headers : headers,
            method : 'GET' },
        callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var possibleQueryStrings = ['compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'id','timeCreatedGreaterThanOrEqualTo','timeCreatedLessThan', 'displayName', 'lifecycleState'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

    ocirest.process( auth,
                   { path : auth.RESTversion + '/waasPolicies' + queryString,
                     host : endpoint.service.waas[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    get: get
};
