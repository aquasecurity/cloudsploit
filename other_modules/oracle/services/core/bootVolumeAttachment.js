var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function attach( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/bootVolumeAttachments/',
                     host : endpoint.service.core[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/bootVolumeAttachments/' + 
                            encodeURIComponent(parameters.bootVolumeAttachmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['availabilityDomain', 'compartmentId', 'limit', 'page', 'instanceId', 'bootVolumeId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth, 
                   { path : auth.RESTversion + '/bootVolumeAttachments/' + queryString,
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' }, 
                   callback );
}


module.exports = {
    list: list,
    attach: attach,
    get: get
    };
