var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/databases/' +
                              encodeURIComponent(parameters.databaseId) + 
                              '/dataGuardAssociations' ,
                       host : endpoint.service.database[auth.region],
                       method : 'POST',
                       headers : headers,
                       body : parameters.body },
                     callback );
  };

function failover( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/databases/' +
                              encodeURIComponent(parameters.databaseId) + 
                              '/dataGuardAssociations/' +
                              encodeURIComponent(parameters.dataGuardAssociationsId) +
                              '/actions/failover',
                       host : endpoint.service.database[auth.region],
                       method : 'POST',
                       headers : headers,
                       body : parameters.body },
                     callback );
  };

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/databases/' +
                              encodeURIComponent(parameters.databaseId) + 
                              '/dataGuardAssociations/' +
                              encodeURIComponent(parameters.dataGuardAssociationsId) +
                              '/actions/failover',
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'GET',
                       },
                     callback );
  };

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

    ocirest.process( auth,
                     { path : auth.RESTversion + '/databases/' +
                              encodeURIComponent(parameters.databaseId) + 
                              '/dataGuardAssociations' + queryString,
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  };

function reinstate( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/databases/' +
                            encodeURIComponent(parameters.databaseId) + 
                            '/dataGuardAssociations/' + 
                            encodeURIComponent(parameters.dataGuardAssociationsId) +
                            '/actions/reinstate',
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : parameters.body },
                   callback );
  };

function switchOver( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/databases/' +
                            encodeURIComponent(parameters.databaseId) + 
                            '/dataGuardAssociations/' + 
                            encodeURIComponent(parameters.dataGuardAssociationsId) +
                            '/actions/switchover',
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : parameters.body },
                   callback );
  };


  module.exports = {
      create: create,
      failover: failover,
      get: get,
      list : list,
      reinstate : reinstate,
      switchOver: switchOver
  }