var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

// This call must be overridden because the
// default call retrieves every snapshot
// available, including public ones

module.exports = function(AWSConfig, collection, retries, callback) {
    var ec2 = new AWS.EC2(AWSConfig);
    var sts = new AWS.STS(AWSConfig);
    var paginating = false;

    helpers.makeCustomCollectorCall(sts, 'getCallerIdentity', {}, retries, null, null, null, function(stsErr, stsData) {
        if (stsErr || !stsData.Account) {
            collection.ec2.describeSnapshots[AWSConfig.region].err = 'Unable to filter by owner ID';
            return callback();
        }

        var params = {
            MaxResults: 1000,
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

        var paginateCb = function(err, data) {
            if (err) {
                collection.ec2.describeSnapshots[AWSConfig.region].err = err;
            } else if (data) {
                if (paginating && data.Snapshots && data.Snapshots.length &&
                    collection.ec2.describeSnapshots[AWSConfig.region].data &&
                    collection.ec2.describeSnapshots[AWSConfig.region].data.length) {
                    collection.ec2.describeSnapshots[AWSConfig.region].data = collection.ec2.describeSnapshots[AWSConfig.region].data.concat(data.Snapshots);
                } else if (!paginating) {
                    collection.ec2.describeSnapshots[AWSConfig.region].data = data.Snapshots;
                }
                if (data.NextToken &&
                    collection.ec2.describeSnapshots[AWSConfig.region].data &&
                    collection.ec2.describeSnapshots[AWSConfig.region].data.length) {
                    paginating = true;
                    return execute(data.NextToken);
                }
            }

            callback();
        };
        function execute(nextToken) { // eslint-disable-line no-inner-declarations
            var localParams = JSON.parse(JSON.stringify(params || {}));
            if (nextToken) localParams['NextToken'] = nextToken;
            if (nextToken) {
                helpers.makeCustomCollectorCall(ec2, 'describeSnapshots', localParams, retries, null, null, null, paginateCb);
            } else {
                helpers.makeCustomCollectorCall(ec2, 'describeSnapshots', params, retries, null, null, null, paginateCb);
            }
        }
        execute();
    });
};
