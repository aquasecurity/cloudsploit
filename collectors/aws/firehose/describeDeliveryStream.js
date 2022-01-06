var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var firehose = new AWS.Firehose(AWSConfig);

    async.eachLimit(collection.firehose.listDeliveryStreams[AWSConfig.region].data, 15, function(deliverystream, cb){
        collection.firehose.describeDeliveryStream[AWSConfig.region][deliverystream] = {};

        var params = {
            DeliveryStreamName: deliverystream
        };

        helpers.makeCustomCollectorCall(firehose, 'describeDeliveryStream', params, retries, null, null, null, function(err, data) {
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