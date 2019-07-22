var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function update( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id','opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/backendSets/' + encodeURIComponent( parameters.backendSetName) +
                            '/healthChecker',
                     host : endpoint.service.loadBalance[auth.region],
                     method : 'PUT',
                     'opc-retry-token' : parameters['opc-retry-token'],
                     'opc-request-id' : parameters['opc-request-id'],
                     body : parameters.body },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/backendSets/' + encodeURIComponent( parameters.backendSetName) +
                            '/healthChecker',
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    update: update,
    get: get
    };
