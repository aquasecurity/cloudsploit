var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
  var possibleHeaders = ['x-amz-date'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/',
                     host : endpoint.service.amazon[auth.region].replace('<object_storage_namespace>',auth.objectStorageName),
                     method : 'GET',
                     headers : headers },
                   callback );
};

module.exports = {
  get: get
  };