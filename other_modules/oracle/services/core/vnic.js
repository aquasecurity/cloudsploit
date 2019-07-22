var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vnics/' + encodeURIComponent(parameters.vnicId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth, 
                   { path : auth.RESTversion + '/vnics/' + encodeURIComponent(parameters.vnicId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     body : parameters.body,
                     method : 'PUT' }, 
                   callback );
}

module.exports = {
    get: get,
    update: update
    };
