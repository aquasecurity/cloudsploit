var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudtrail = new AWS.CloudTrail(AWSConfig);

    async.eachLimit(collection.cloudtrail.describeTrails[AWSConfig.region].data, 15, function(trail, cb) {
        var params = {
            ResourceIdList: [trail.TrailARN]
        };

        helpers.makeCustomCollectorCall(cloudtrail, 'listTags', params, retries, null, null, null, function(err, data) {
            collection.cloudtrail.listTags[AWSConfig.region][trail.TrailARN] = {};
            if (err || !data) {
                collection.cloudtrail.listTags[AWSConfig.region][trail.TrailARN].err = err;
            } else {
                collection.cloudtrail.listTags[AWSConfig.region][trail.TrailARN].data = data;
            }
            cb();
        });
    }, function() {
        callback();
    });
};
