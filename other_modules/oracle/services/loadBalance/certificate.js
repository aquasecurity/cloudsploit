var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/certificates',
                     host : endpoint.service.loadBalance[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/certificates/' + encodeURIComponent(parameters.certificateName),
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/certificates',
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    create: create,
    drop: drop
    };
