var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Multiple networks/subnets are used in a VPC',
	category: 'VPC',
	description: 'Ensures that VPC has multiple networks which provides a layered architecture',
	more_info: 'A single network within a VPC exposes of a risk of increasing the impact radius in case of a compromisation.',
	link: 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#SubnetSecurity',
	recommended_action: 'Create multiple networks/subnets and change your architecture',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};
		var vpcId;

		async.eachLimit(helpers.regions.vpc, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			var params = {

			};

			ec2.describeVpcs(params, function(err, data){
				if (includeSource) source[region] = {error: err, data: data};

				if (err || !data || !data.Vpcs) {
					results.push({
						status: 3,
						message: 'Unable to query for VPCs',
						region: region
					});

					return rcb();
				}

				// First check if there are multiple VPCs, because they may use VPCs instead of subnets
				if (data.Vpcs.length > 1) {
					results.push({
						status: 0,
						message: 'Multiple (' + data.Vpcs.length + ') VPCs are used.',
						region: region
					});

					return rcb();
				} else {
					// Looks like we have only one VPC
					vpcId = data.Vpcs[0].VpcId;


					// Check for the multiple subnets in that single VPC
					var params = {
						Filters: [
							{
								Name: "vpc-id",
								Values: [
									vpcId
								]
							}
						]
					}

					if (!vpcId) {
						results.push({
							status: 3,
							message: 'Unable to query for Subnets.',
							region: region
						});

						return rcb();
					}

					ec2.describeSubnets(params, function(err, data) {
						if (includeSource) source[region] = {error: err, data: data};

						if (err || !data || !data.Subnets) {
							results.push({
								status: 3,
								message: 'Unable to query for Subnets.',
								region: region
							});

							return rcb();
						}

						if (data.Subnets.length > 2) {
							results.push({
								status: 0,
								message: 'There are ' + data.Subnets.length + ' different CIDR Blocks used in one VPC.',
								region: region,
								resource: vpcId
							});
						} else if (data.Subnets.length > 1) {
							results.push({
								status: 1,
								message: 'Using ' + data.Subnets.length + ' subnets may not be sufficient for a multi-layered architecture',
								region: region,
								resource: vpcId
							});
						} else {
							results.push({
								status: 2,
								message: 'Only one subnet, one VPC is used.',
								region: region,
								resource: vpcId + ' & ' + data.Subnets[0].SubnetId
							});
						}

						rcb();
					});
				}
			});
		}, function(){
			callback(null, results, source);
		});
	}
};
