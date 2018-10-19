var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
	var ec2 = new AWS.EC2(AWSConfig);

	async.eachLimit(collection.ec2.describeVpcs[AWSConfig.region].data, 15, function(vpc, cb){
		collection.ec2.describeSubnets[AWSConfig.region][vpc.VpcId] = {};

		// Check for the multiple subnets in that single VPC
		var params = {
			Filters: [
				{
					Name: "vpc-id",
					Values: [
						vpc.VpcId
					]
				}
			]
		};

		ec2.describeSubnets(params, function(err, data) {
			if (err) {
				collection.ec2.describeSubnets[AWSConfig.region][vpc.VpcId].err = err;
			}

			collection.ec2.describeSubnets[AWSConfig.region][vpc.VpcId].data = data;

			cb();
		});
	}, function(){
		callback();
	});
};