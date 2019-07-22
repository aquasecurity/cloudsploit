var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers' + encodeURIComponent(parameters.loadBalancerId) +
                            '/hostnames',
                     host : endpoint.service.loadBalance[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers' + encodeURIComponent(parameters.loadBalancerId) +
                            '/hostnames/' + encodeURIComponent(parameters.name),
                     host : endpoint.service.loadBalance[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers' + encodeURIComponent(parameters.loadBalancerId) +
                            '/hostnames/' + encodeURIComponent(parameters.name),
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers' + encodeURIComponent(parameters.loadBalancerId) +
                            '/hostnames/' + encodeURIComponent(parameters.name),
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/loadBalancers/' + encodeURIComponent(parameters.loadBalancerId) +
                            '/hostnames',
                     host : endpoint.service.loadBalance[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

module.exports = {
    list: list,
    update: update,
    get: get,
    create: create,
    drop: drop
    };
