var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancerWorkRequests/' + encodeURIComponent(parameters.workRequestId) +
                            '/pathRouteSets/' + encodeURIComponent(parameters.pathRouteSetName),
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var possibleQueryStrings = ['limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancerWorkRequests/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/workRequests' + queryString,
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    get: get
    };
