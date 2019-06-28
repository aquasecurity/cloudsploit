var AWS = require('aws-sdk');

// This call must be overridden because the
// default call retrieves every snapshot
// available, including public ones

module.exports = function(AWSConfig, collection, callback) {
    var ec2 = new AWS.EC2(AWSConfig);
    var sts = new AWS.STS(AWSConfig);

    sts.getCallerIdentity({}, function(stsErr, stsData) {
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

        ec2.describeSnapshots(params, function(err, data){
            if (err) {
                collection.ec2.describeSnapshots[AWSConfig.region].err = err;
            } else {
                collection.ec2.describeSnapshots[AWSConfig.region].data = data.Snapshots;
            }

            callback();
        });
    });
};