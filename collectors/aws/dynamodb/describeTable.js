var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var dynamodb = new AWS.DynamoDB(AWSConfig);

    async.eachLimit(collection.dynamodb.listTables[AWSConfig.region].data, 15, function(table, cb){
        collection.dynamodb.describeTable[AWSConfig.region][table] = {};
        var params = {
            'TableName': table
        };

        dynamodb.describeTable(params, function(err, data) {
            if (err) {
                collection.dynamodb.describeTable[AWSConfig.region][table].err = err;
            }
            collection.dynamodb.describeTable[AWSConfig.region][table].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
