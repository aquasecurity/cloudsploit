var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ec2 = new AWS.EC2(AWSConfig);

    async.eachLimit(collection.ec2.describeSnapshots[AWSConfig.region].data, 15, function(snapshot, cb){
        collection.ec2.describeSnapshotAttribute[AWSConfig.region][snapshot.SnapshotId] = {};
        var params = {
            Attribute: 'createVolumePermission',
            SnapshotId: snapshot.SnapshotId
        };

        helpers.makeCustomCollectorCall(ec2, 'describeSnapshotAttribute', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ec2.describeSnapshotAttribute[AWSConfig.region][snapshot.SnapshotId].err = err;
            }
            collection.ec2.describeSnapshotAttribute[AWSConfig.region][snapshot.SnapshotId].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
