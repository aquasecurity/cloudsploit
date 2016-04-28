var async = require('async');
var AWS = require('aws-sdk');
var sts = new AWS.STS({apiVersion: '2011-06-15'});
var plugins = require(__dirname + '/exports.js');

function createSuccessResponse(data) {
    return {
        code: 0,
        data: data
    };
}

function createErrorResponse(error, code) {
    return {
        code: code || 1,
        message: error
    };
}

var pluginsList = [];
var pluginQueries = [];

for (i in plugins) {
    pluginsList.push({
        title: plugins[i].title,
        query: i,
        description: plugins[i].description
    });
    pluginQueries.push(i);
}

var pluginRunner = function(event, context) {
    if (event.plugins) {
        var resultsToSend = [];

        if (!event.plugins.length) {
            event.plugins = pluginQueries;
        }

        async.eachLimit(event.plugins, 10, function(pluginToRun, cb){
            console.log('Running: ' + pluginToRun);
            // Run the plugin requested
            plugins[pluginToRun].run({}, function(err, results){
                if (err) {
                    console.log(err);
                } else {
                    resultsToSend.push(results);
                }

                cb();
            });
        }, function(){
            context.succeed(createSuccessResponse(resultsToSend));
        });
    } else {
        context.succeed(createSuccessResponse(pluginsList));
    }
};

exports.handler = pluginRunner;