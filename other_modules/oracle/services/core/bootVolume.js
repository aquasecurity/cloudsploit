var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');


function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/bootVolumes',
                     host : endpoint.service.core[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/bootVolumes/' + 
                            encodeURIComponent(parameters.bootVolumeId),
                     host : endpoint.service.core[auth.region],
                     method : 'DELETE',
                     headers : headers },
                    callback )
}

function detach( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/bootVolumeAttachments/' + 
                            encodeURIComponent(parameters.bootVolumeAttachmentId),
                     host : endpoint.service.core[auth.region],
                     method : 'DELETE',
                     headers : headers },
                    callback )
}


function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/bootVolumes/' + 
                            encodeURIComponent(parameters.bootVolumeId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['availabilityDomain', 'compartmentId', 'volumnGroupId', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth, 
                   { path : auth.RESTversion + '/bootVolumes' + queryString,
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path: auth.RESTversion + '/bootVolumes/' + 
                           encodeURIComponent(parameters.bootVolumeId),
                     host : endpoint.service.core[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

module.exports = {
    list: list,
    update: update,
    get: get,
    detach: detach,
    create: create,
    drop: drop
    };
