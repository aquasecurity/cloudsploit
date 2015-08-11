// Plugins can be executed by AWS Lambda
// Pass in either an access_key and secret_key or an IAM execution role / external ID

var plugins = require(__dirname + '/exports.js');
var AWS = require('aws-sdk');
var sts = new AWS.STS({apiVersion: '2011-06-15'});
var regions = require(__dirname + '/regions.json');

exports.handler = function(event, context) {
    console.log('Received event:', JSON.stringify(event, null, 2));

    // Validations

    if (event.role) {
        if (event.role.indexOf('arn:aws:iam::') == -1) {
            return context.fail(new Error('Invalid role'));
        }

        if (!event.external_id || !/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/.test(event.external_id)) {
            return context.fail(new Error('Invalid external id'));
        }
    } else {
        if (!event.access_key || !/^([A-Z0-9]){20}$/.test(event.access_key)) {
            return context.fail(new Error('Invalid access key'));
        }

        if (!event.secret_key || !/^([A-Za-z0-9\/+=]){40}$/.test(event.secret_key)) {
            return context.fail(new Error('Invalid secret key'));
        }

        if (event.session_token && !/^([a-zA-Z0-9\\\/\.$&*()@#+=]){100,1000}$/.test(event.session_token)) {
            return context.fail(new Error('Invalid session token'));
        }
    }

    if (!event.region || !regions.indexOf(event.region) == -1) {
        return context.fail(new Error('Invalid region'));
    }

    if (!event.plugin || !plugins[event.plugin]) {
        return context.fail(new Error('Invalid plugin'));
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
                return context.fail(new Error('Unable to assume cross-account role'));
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
        var AWSConfig = {
            accessKeyId: event.access_key,
            secretAccessKey: event.secret_key,
            region: event.region
        };

        if (event.session_token) {
            AWSConfig.sessionToken = event.session_token;
        }

        // Run the plugin requested
        plugins[event.plugin].run(AWSConfig, function(err, results){
            if (err) {
                console.log(err);
                return context.fail(new Error('Error result from plugin'));
            }

            context.succeed(results);
        });
    }
};