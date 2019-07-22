var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
  var possibleQueryStrings = ['ids','limit','offset','orderBy','purchaseEntitlementId',
                              'serviceDefinitionName','serviceEntitlementId','statuses'];
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/itas/' + encodeURIComponent(parameters.domain) +
                            '/myservices/api' + auth.RESTversion +
                            '/serviceInstances' + queryString,
                     host : endpoint.service.myServices,
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    get: get
    };