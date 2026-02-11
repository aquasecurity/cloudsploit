var { EC2Client, DescribeAddressesCommand } = require('@aws-sdk/client-ec2');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    
    var ec2Client = new EC2Client(helpers.buildV3ClientConfig(AWSConfig));

    var params = {};

    helpers.makeCustomCollectorCallV3(ec2Client, DescribeAddressesCommand, params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.ec2.describeAddresses[AWSConfig.region].err = err;
        } else if (data) {
            collection.ec2.describeAddresses[AWSConfig.region].data = data.Addresses || [];
        } else if (!collection.ec2.describeAddresses[AWSConfig.region].data) {
            collection.ec2.describeAddresses[AWSConfig.region].data = [];
        }

        callback();
    });
};
