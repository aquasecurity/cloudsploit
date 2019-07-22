var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vaults',
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
                   { path : auth.RESTversion + '/vaults/' + encodeURIComponent(parameters.vaultId),
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
                   { path : auth.RESTversion + '/vaults/' + encodeURIComponent(parameters.vaultId),
                     host : endpoint.service.kms[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function scheduleDeletion( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vaults/' + encodeURIComponent(parameters.vaultId) +
                            '/actions/scheduleDeletion',
                     host : endpoint.service.kms[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function cancelDeletion( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id', 'opc-retry-token', 'if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vaults/' + encodeURIComponent(parameters.vaultId) +
                            '/actions/cancelDeletion',
                     host : endpoint.service.kms[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

module.exports = {
    update: update,
    get: get,
    create: create,
    scheduleDeletion: scheduleDeletion,
    cancelDeletion: cancelDeletion
    };
