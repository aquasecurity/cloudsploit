var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
    var possibleHeaders = [];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/ipsecConnections/' + encodeURIComponent(parameters.ipscId) +
                              '/deviceStatus',
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

  module.exports={
      get: get
  }