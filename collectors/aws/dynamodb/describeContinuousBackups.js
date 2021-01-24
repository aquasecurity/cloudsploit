var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var dynamodb = new AWS.DynamoDB(AWSConfig);

    async.eachLimit(collection.dynamodb.listTables[AWSConfig.region].data, 15, function(table, cb){
        collection.dynamodb.describeContinuousBackups[AWSConfig.region][table] = {};
        var params = {
            'TableName': table
        };

        dynamodb.describeContinuousBackups(params, function(err, data) {
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
