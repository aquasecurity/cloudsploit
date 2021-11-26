var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var connect = new AWS.Connect(AWSConfig);

    async.eachLimit(collection.connect.listInstances[AWSConfig.region].data, 15, function(instance, cb){
        collection.connect.listInstanceChatTranscriptStorageConfigs[AWSConfig.region][instance.Id] = {};
        var params = {
            'InstanceId': instance.Id,
            'ResourceType': 'CHAT_TRANSCRIPTS'
        };

        connect.listInstanceStorageConfigs(params, function(err, data) {
            if (err) {
                collection.connect.listInstanceChatTranscriptStorageConfigs[AWSConfig.region][instance.Id].err = err;
            }
            collection.connect.listInstanceChatTranscriptStorageConfigs[AWSConfig.region][instance.Id].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
