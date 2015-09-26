// Plugins can be executed by AWS Lambda
// Pass in either an access_key and secret_key or an IAM execution role / external ID

var plugins = require(__dirname + '/exports.js');
var AWS = require('aws-sdk');
var sts = new AWS.STS({apiVersion: '2011-06-15'});
var regions = require(__dirname + '/regions.json');

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

for (i in plugins) {
    pluginsList.push({
        title: plugins[i].title,
        query: plugins[i].query,
        description: plugins[i].description
    });
}

exports.handler = function(event, context) {
    try {
        var copiedEvent = JSON.parse(JSON.stringify(event));
        if (copiedEvent.secret_key) {
            copiedEvent.secret_key = copiedEvent.secret_key.substring(0,1) + '**************************************' + copiedEvent.secret_key.substring(copiedEvent.secret_key.length - 1);
        }

        if (copiedEvent.session_token) {
            copiedEvent.session_token = copiedEvent.session_token.substring(0,1) + '**************************************' + copiedEvent.session_token.substring(copiedEvent.session_token.length - 1);
        }
        console.log('Received event:', JSON.stringify(copiedEvent, null, 2));
    } catch (e) {
        console.log('Received event:', JSON.stringify(event, null, 2))
    }

    if (!event.role && !event.access_key && !event.secret_key && !event.external_id && !event.session_token && !event.plugin) {
        // Treat as a list of all plugins available
        return context.succeed(createSuccessResponse({plugins:pluginsList}));
    }

    // Validations

    if (event.role) {
        if (event.role.indexOf('arn:aws:iam::') == -1) {
            return context.succeed(createErrorResponse('Invalid role'));
        }

        if (!event.external_id || !/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/.test(event.external_id)) {
            return context.succeed(createErrorResponse('Invalid external id'));
        }
    } else if (event.access_key || event.secret_key || event.session_token) {
        if (!event.access_key || !/^([A-Z0-9]){20}$/.test(event.access_key)) {
            return context.succeed(createErrorResponse('Invalid access key'));
        }

        if (!event.secret_key || !/^([A-Za-z0-9\/+=]){40}$/.test(event.secret_key)) {
            return context.succeed(createErrorResponse('Invalid secret key'));
        }

        if (event.session_token && !/^([a-zA-Z0-9\\\/\.$&*()@#+=]){100,1000}$/.test(event.session_token)) {
            return context.succeed(createErrorResponse('Invalid session token'));
        }
    }

    if (!event.region || !regions.indexOf(event.region) == -1) {
        return context.succeed(createErrorResponse('Invalid region'));
    }

    if (!event.plugin || !plugins[event.plugin]) {
        return context.succeed(createErrorResponse('Invalid plugin'));
    }

    if (event.role) {
        // retrieve temporary tokens from an IAM role
        var params = {
            RoleArn: event.role, /* required */
            RoleSessionName: 'cloudsploit_scan', /* required */
            DurationSeconds: 900,   // only valid for fifteen minutes
            ExternalId: event.external_id,
            // Policy: 'STRING_VALUE',
            // SerialNumber: 'STRING_VALUE',
            // TokenCode: 'STRING_VALUE'
        };

        sts.assumeRole(params, function(err, data){
            if (err || !data.Credentials || !data.Credentials.AccessKeyId || !data.Credentials.SecretAccessKey || !data.Credentials.SessionToken) {
                console.log(err);
                return context.succeed(createErrorResponse('Unable to assume cross-account role'));
            }

            // Set credentials
            event.access_key = data.Credentials.AccessKeyId;
            event.secret_key = data.Credentials.SecretAccessKey;
            event.session_token = data.Credentials.SessionToken;

            callPlugin();
        });
    } else {
        callPlugin();
    }

    function callPlugin() {

        var AWSConfig = {};

        if (event.access_key) {
          AWSConfig = {
              accessKeyId: event.access_key,
              secretAccessKey: event.secret_key,
              region: event.region
          };
        }

        if (event.session_token) {
            AWSConfig.sessionToken = event.session_token;
        }

        // Run the plugin requested
        plugins[event.plugin].run(AWSConfig, function(err, results){
            if (err) {
                console.log(err);
                return context.succeed(createErrorResponse('Error result from plugin'));
            }

            context.succeed(createSuccessResponse(results));
        });
    }
};
