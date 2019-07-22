var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function createOrReset( auth, parameters, callback ) {
    var possibleHeaders = ['opc-retry-token'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                             '/users/' + encodeURIComponent(parameters.userId) +
                             '/uiPassword',
                       host : endpoint.service.iam[auth.region],
                       method : 'POST',
                       body : parameters.body,
                       headers : headers },
                      callback )
  }

  module.exports={
      createOrReset: createOrReset
  }