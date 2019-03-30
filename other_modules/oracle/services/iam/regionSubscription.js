var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
    var possibleHeaders = ['opc-retry-token'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/tenancies/' + encodeURIComponent(parameters.tenancyId) +
                              '/regionSubscriptions',
                       host : endpoint.service.iam[auth.region],
                       method : 'POST',
                       headers : headers,
                       body : parameters.body },
                      callback )
  };

function list( auth, parameters, callback ) {
    var possibleHeaders = [];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/tenancies/' + encodeURIComponent(parameters.tenancyId) +
                              '/regionSubscriptions',
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

  module.exports={
      list: list,
      create: create
  }