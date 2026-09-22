var async = require('async');
var { EC2Client, DescribeAddressesCommand } = require('@aws-sdk/client-ec2');
var helpers = require(__dirname + '/../../../helpers/aws');

var rateError = { message: 'rate', statusCode: 429 };
var apiRetryAttempts = 2;
var apiRetryCap = 1000;
var apiRetryBackoff = 500;

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {

    var ec2Client = new EC2Client(helpers.buildV3ClientConfig(AWSConfig));
    var params = {};

    function runOnce(cb) {
        var command = new DescribeAddressesCommand(params);
        ec2Client.send(command).then(function(data) {
            return cb(null, data);
        }).catch(function(err) {
            helpers.refreshCredentialsIfTokenExpired(err, settings, scanAWSConfig, AWSConfig, function(refreshErr, newCreds) {
                if (!newCreds) {
                    if (refreshErr) console.log('[WARN] Token refresh failed');
                    return cb(err, null);
                }
                try {
                    ec2Client = new EC2Client(helpers.buildV3ClientConfig(AWSConfig));
                } catch (e) {
                    return cb(err, null);
                }
                var retryCommand = new DescribeAddressesCommand(params);
                ec2Client.send(retryCommand).then(function(data) {
                    return cb(null, data);
                }).catch(function(retryErr) {
                    return cb(retryErr, null);
                });
            });
        });
    }

    async.retry({
        times: apiRetryAttempts,
        interval: function(retryCount) {
            let retryExponential = 3;
            let retryLeveler = 3;
            let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
            let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
            let retry_seconds = Math.round(retry_temp / retryLeveler + Math.random(0, retry_temp) * 5000);

            console.log(`Trying DescribeAddressesCommand again in: ${retry_seconds / 1000} seconds`);
            retries.push({ seconds: Math.round(retry_seconds / 1000) });
            return retry_seconds;
        },
        errorFilter: function(err) {
            return helpers.collectRateError(err, rateError);
        }
    }, function(cb) {
        runOnce(cb);
    }, function(err, data) {
        if (err) {
            collection.ec2.describeAddresses[AWSConfig.region].err = err;
        } else if (data) {
            collection.ec2.describeAddresses[AWSConfig.region].data = data.Addresses || [];
        } else if (!collection.ec2.describeAddresses[AWSConfig.region].data) {
            collection.ec2.describeAddresses[AWSConfig.region].data = [];
        }

        callback();
    });
};
