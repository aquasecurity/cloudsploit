var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id','opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/clusters',
                     host : endpoint.service.containerEngine[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function createKubeConfig( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/clusters' + encodeURIComponent(parameters.clusterId) +
                            '/kubeconfig/content',
                     host : endpoint.service.containerEngine[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}


function update( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/clusters/' + encodeURIComponent(parameters.clusterId),
                     host : endpoint.service.containerEngine[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/clusters/' + encodeURIComponent(parameters.clusterId),
                     host : endpoint.service.containerEngine[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/clusters/' + encodeURIComponent(parameters.clusterId),
                     host : endpoint.service.containerEngine[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
}

module.exports = {
    update: update,
    get: get,
    create: create,
    createKubeConfig: createKubeConfig,
    drop: drop
    };
