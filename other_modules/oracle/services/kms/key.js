var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/keys',
                     host : endpoint.service.kms[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/keys/' + encodeURIComponent(parameters.keyId),
                     host : endpoint.service.kms[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/keys/' + encodeURIComponent(parameters.keyId),
                     host : endpoint.service.kms[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function disable( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id', 'opc-retry-token', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/keys/' + encodeURIComponent(parameters.keyId) +
                            '/actions/disable',
                     host : endpoint.service.kms[auth.region],
                     headers : headers,
                     method : 'POST' },
                    callback );
}

function enable( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id', 'opc-retry-token', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/keys/' + encodeURIComponent(parameters.keyId) +
                            '/actions/enable',
                     host : endpoint.service.kms[auth.region],
                     headers : headers,
                     method : 'POST' },
                    callback );
}


module.exports = {
    update: update,
    get: get,
    create: create,
    disable: disable,
    enable: enable
    };
