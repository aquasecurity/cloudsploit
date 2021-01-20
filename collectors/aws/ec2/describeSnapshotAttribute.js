var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var ec2 = new AWS.EC2(AWSConfig);

    async.eachLimit(collection.ec2.describeSnapshots[AWSConfig.region].data, 15, function(snapshot, cb){
        collection.ec2.describeSnapshotAttribute[AWSConfig.region][snapshot.SnapshotId] = {};
        var params = {
            Attribute: 'createVolumePermission',
            SnapshotId: snapshot.SnapshotId
        };

        ec2.describeSnapshotAttribute(params, function(err, data) {
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
