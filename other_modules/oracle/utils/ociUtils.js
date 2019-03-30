
function buildHeaders( possibleHeaders, options, bString ){
    var headers = {'content-type' : 'application/json'};
    if ( bString )
      headers['content-type'] = 'application/x-www-form-urlencoded';

    for( var i=0; i<possibleHeaders.length; i++ )
        if ( possibleHeaders[i].toLowerCase() in options )
          headers[possibleHeaders[i]] = options[possibleHeaders[i]];
    return headers;
}

function buildQueryString( possibleQuery, options ){
    var query = '';
    for ( var i=0; i<possibleQuery.length; i++ )
      if ( possibleQuery[i] in options )
        query += (query=='' ? '?' : '&' ) + possibleQuery[i] + '=' + encodeURIComponent(options[possibleQuery[i]]);
    return query;
}


module.exports = {
    buildHeaders: buildHeaders,
    buildQueryString: buildQueryString
    };