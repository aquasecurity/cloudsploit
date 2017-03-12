var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'VPC Multiple Subnets',
	category: 'VPC',
	description: 'Ensures that VPCs have multiple networks to provide a layered architecture',
	more_info: 'A single network within a VPC increases the risk of a broader blast radius in the event of a compromise.',
	link: 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#SubnetSecurity',
	recommended_action: 'Create multiple networks/subnets in each VPC and change the architecture to take advantage of public and private tiers.',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		if (includeSource) source['describeVpcs'] = {};
		if (includeSource) source['describeSubnets'] = {};

		async.eachLimit(helpers.regions.vpc, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			helpers.cache(cache, ec2, 'describeVpcs', function(err, data) {
				if (includeSource) source['describeVpcs'][region] = {error: err, data: data};

				if (err || !data || !data.Vpcs || !data.Vpcs.length) {
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
					var vpcId = data.Vpcs[0].VpcId;

					if (!vpcId) {
						results.push({
							status: 3,
							message: 'Unable to query for subnets for VPC.',
							region: region
						});

						return rcb();
					}

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
					};

					ec2.describeSubnets(params, function(subnetErr, subnetData) {
						if (includeSource) source['describeSubnets'][region] = {error: subnetErr, data: subnetData};

						if (subnetErr || !subnetData || !subnetData.Subnets || !subnetData.Subnets.length) {
							results.push({
								status: 3,
								message: 'Unable to query for subnets in VPC.',
								region: region,
								resource: vpcId
							});

							return rcb();
						}

						if (subnetData.Subnets.length > 2) {
							results.push({
								status: 0,
								message: 'There are ' + subnetData.Subnets.length + ' different subnets used in one VPC.',
								region: region,
								resource: vpcId
							});
						} else if (subnetData.Subnets.length > 1) {
							results.push({
								status: 1,
								message: 'Using ' + subnetData.Subnets.length + ' subnets may not be sufficient for a multi-layered architecture',
								region: region,
								resource: vpcId
							});
						} else {
							results.push({
								status: 2,
								message: 'Only one subnet (' + subnetData.Subnets[0].SubnetId + ') in one VPC is used.',
								region: region,
								resource: vpcId
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
