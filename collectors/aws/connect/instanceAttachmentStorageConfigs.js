var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var connect = new AWS.Connect(AWSConfig);

    async.eachLimit(collection.connect.listInstances[AWSConfig.region].data, 15, function(instance, cb){
        collection.connect.instanceAttachmentStorageConfigs[AWSConfig.region][instance.Id] = {};
        var params = {
            'InstanceId': instance.Id,
            'ResourceType': 'ATTACHMENTS'
        };

        connect.listInstanceStorageConfigs(params, function(err, data) {
            if (err) {
                collection.connect.instanceAttachmentStorageConfigs[AWSConfig.region][instance.Id].err = err;
            }
            collection.connect.instanceAttachmentStorageConfigs[AWSConfig.region][instance.Id].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
