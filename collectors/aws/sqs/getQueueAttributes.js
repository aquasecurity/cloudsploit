var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var sqs = new AWS.SQS(AWSConfig);

    async.eachLimit(collection.sqs.listQueues[AWSConfig.region].data, 15, function(queue, cb){
        collection.sqs.getQueueAttributes[AWSConfig.region][queue] = {};

        var params = {
            QueueUrl: queue,
            AttributeNames: [
                'All'
            ]
        };

        helpers.makeCustomCollectorCall(sqs, 'getQueueAttributes', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.sqs.getQueueAttributes[AWSConfig.region][queue].err = err;
            }
            collection.sqs.getQueueAttributes[AWSConfig.region][queue].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};