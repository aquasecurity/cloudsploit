var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var cloudtrail = new AWS.CloudTrail(AWSConfig);

    async.eachLimit(collection.cloudtrail.describeTrails[AWSConfig.region].data, 15, function(trail, cb) {
        var params = {
            ResourceIdList: [trail.TrailARN]
        };

        cloudtrail.listTags(params, function(err, data) {
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
