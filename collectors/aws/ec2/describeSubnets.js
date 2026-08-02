const {
    EC2
} = require('@aws-sdk/client-ec2');

var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ec2 = new EC2(AWSConfig);

    async.eachLimit(collection.ec2.describeVpcs[AWSConfig.region].data, 15, function(vpc, cb){
        collection.ec2.describeSubnets[AWSConfig.region][vpc.VpcId] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            Filters: [
                {
                    Name: 'vpc-id',
                    Values: [
                        vpc.VpcId
                    ]
                }
            ]
        };

        helpers.makeCustomCollectorCall(ec2, 'describeSubnets', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ec2.describeSubnets[AWSConfig.region][vpc.VpcId].err = err;
            }

            if (data) collection.ec2.describeSubnets[AWSConfig.region][vpc.VpcId].data = data;

            cb();
        });
    }, function(){
        callback();
    });
};