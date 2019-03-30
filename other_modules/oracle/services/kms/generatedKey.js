var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function generate( auth, parameters, callback ){
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTVersion + '/generateDataEncryptionKey',
                       host : endpoint.service.kms[auth.region],
                       body : parameters.body,
                       headers : headers,
                       method : 'POST' },
                     callback );
  }

module.exports = {
  generate : generate
}