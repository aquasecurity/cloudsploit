var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var connect = new AWS.Connect(AWSConfig);

    async.eachLimit(collection.connect.listInstances[AWSConfig.region].data, 15, function(instance, cb){
        collection.connect.listInstanceExportedReportStorageConfigs[AWSConfig.region][instance.Id] = {};
        var params = {
            'InstanceId': instance.Id,
            'ResourceType': 'SCHEDULED_REPORTS'
        };

        helpers.makeCustomCollectorCall(connect, 'listInstanceStorageConfigs', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.connect.listInstanceExportedReportStorageConfigs[AWSConfig.region][instance.Id].err = err;
            }
            collection.connect.listInstanceExportedReportStorageConfigs[AWSConfig.region][instance.Id].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
