var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var dynamodb = new AWS.DynamoDB(AWSConfig);

    async.eachLimit(collection.dynamodb.listTables[AWSConfig.region].data, 15, function(table, cb){
        collection.dynamodb.describeContinuousBackups[AWSConfig.region][table] = {};
        var params = {
            'TableName': table
        };

        helpers.makeCustomCollectorCall(dynamodb, 'describeContinuousBackups', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.dynamodb.describeContinuousBackups[AWSConfig.region][table].err = err;
            }
            collection.dynamodb.describeContinuousBackups[AWSConfig.region][table].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
