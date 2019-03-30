var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
  var possibleHeaders = ['opc-request-id'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/nodePoolOptions/' + encodeURIComponent(parameters.nodePoolOptionId),
                     host : endpoint.service.containerEngine[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    get: get
    };
