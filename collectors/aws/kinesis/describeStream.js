var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var kinesis = new AWS.Kinesis(AWSConfig);

    async.eachLimit(collection.kinesis.listStreams[AWSConfig.region].data, 15, function(stream, cb){
        collection.kinesis.describeStream[AWSConfig.region][stream] = {};

        var params = {
            StreamName: stream
        };

        helpers.makeCustomCollectorCall(kinesis, 'describeStream', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.kinesis.describeStream[AWSConfig.region][stream].err = err;
            }
            collection.kinesis.describeStream[AWSConfig.region][stream].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};