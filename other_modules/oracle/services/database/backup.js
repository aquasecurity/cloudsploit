var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/backups' ,
                       host : endpoint.service.database[auth.region],
                       method : 'POST',
                       headers: headers,
                       body : parameters.body },
                     callback );
  };

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/backups/'  +
                              encodeURIComponent(parameters.backupId),
                       host : endpoint.service.database[auth.region],
                       method : 'DELETE',
                       headers: headers },
                     callback );
  };


function get( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/backups/'  +
                              encodeURIComponent(parameters.backupId),
                       host : endpoint.service.database[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  };

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['databaseId', 'compartmentId', 'limit', 'page' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/backups' + queryString,
                       host : endpoint.service.database[auth.region],
                       method : 'POST',
                       headers : headers,
                       body : parameters.body },
                     callback );
  };


  module.exports = {
      create: create,
      drop: drop,
      get: get,
      list: list
  }