var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

// This call must be overridden because the
// default call retrieves every snapshot
// available, including public ones

module.exports = function(AWSConfig, collection, retries, callback) {
    var ec2 = new AWS.EC2(AWSConfig);
    var sts = new AWS.STS(AWSConfig);

    helpers.makeCustomCollectorCall(sts, 'getCallerIdentity', {}, retries, null, null, null, function(stsErr, stsData) {
        if (stsErr || !stsData.Account) {
            collection.ec2.describeSnapshots[AWSConfig.region].err = 'Unable to filter by owner ID';
            return callback();
        }

        var params = {
            Filters: [
                {
                    Name: 'owner-id',
                    Values: [
                        stsData.Account
                    ]
                },
                {
                    Name: 'status',
                    Values: [
                        'completed'
                    ]
                }
            ]
        };

        helpers.makeCustomCollectorCall(ec2, 'describeSnapshots', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ec2.describeSnapshots[AWSConfig.region].err = err;
            } else {
                collection.ec2.describeSnapshots[AWSConfig.region].data = data.Snapshots;
            }
            callback();
        });
    });
};