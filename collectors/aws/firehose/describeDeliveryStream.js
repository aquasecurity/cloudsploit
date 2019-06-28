var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var firehose = new AWS.Firehose(AWSConfig);

    async.eachLimit(collection.firehose.listDeliveryStreams[AWSConfig.region].data, 15, function(deliverystream, cb){
        collection.firehose.describeDeliveryStream[AWSConfig.region][deliverystream] = {};

        var params = {
            DeliveryStreamName: deliverystream
        };

        firehose.describeDeliveryStream(params, function(err, data) {
            if (err) {
                collection.firehose.describeDeliveryStream[AWSConfig.region][deliverystream].err = err;
            }
            collection.firehose.describeDeliveryStream[AWSConfig.region][deliverystream].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};