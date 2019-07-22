var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbHomes',
                     host : endpoint.service.database[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body },
                   callback );
  }

  function drop( auth, parameters, callback ) {
    var possibleHeaders = ['if-match'];
    var possibleQueryStrings = ['preformFinalBackup'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/dbHomes/' +
                              encodeURIComponent(parameters.dbHomeId) + queryString,
                       host : endpoint.service.database[auth.region],
                       method : 'DELETE',
                       headers : headers },
                     callback );
  }
 
function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbHomes/' + encodeURIComponent(parameters.dbHomeId),
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
  }

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['dbSystemId', 'compartmentId', 'limit', 'page', 'sortBy', 'sortOrder', 'lifecycleState', 'displayName' ];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    
  ocirest.process( auth,
                   { path : auth.RESTversion + '/dbHomes' + queryString,
                     host : endpoint.service.database[auth.region],
                     headers : headers,
                     method : 'GET' },
                   callback );
  }

  function update( auth, parameters, callback ) {
    var possibleHeaders = ['if-match'];
    var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/dbHomes/' +
                              encodeURIComponent(parameters.dbHomeId),
                       host : endpoint.service.database[auth.region],
                       method : 'PUT',
                       headers : headers,
                       body : parameters.body },
                     callback );
  }
 

module.exports = {
    create: create,
    drop: drop,
    get: get,
    list: list,
    update: update
}