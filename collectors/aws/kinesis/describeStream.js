var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var kinesis = new AWS.Kinesis(AWSConfig);

    async.eachLimit(collection.kinesis.listStreams[AWSConfig.region].data, 15, function(stream, cb){
        collection.kinesis.describeStream[AWSConfig.region][stream] = {};

        var params = {
            StreamName: stream
        };

        kinesis.describeStream(params, function(err, data) {
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