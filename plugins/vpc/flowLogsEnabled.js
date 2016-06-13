var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'VPC Flow Logs Enabled',
	category: 'VPC',
	description: 'Ensures VPC flow logs are enabled for traffic logging',
	more_info: 'VPC flow logs record all traffic flowing in to and out of a VPC. These logs are critical for auditing and review after security incidents.',
	link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html',
	recommended_action: 'Enable VPC flow logs for each VPC',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.eachLimit(helpers.regions.flowlogs, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			helpers.cache(cache, ec2, 'describeVpcs', function(err, data) {
				if (err || !data || !data.Vpcs) {
					results.push({
						status: 3,
						message: 'Unable to query for VPCs',
						region: region
					});

					return rcb();
				}

				// Perform checks for establishing if MFA token is enabled
				if (!data.Vpcs.length) {
					results.push({
						status: 0,
						message: 'No VPCs found',
						region: region
					});

					return rcb();
				}

				var vpcMap = {};

				for (i in data.Vpcs) {
					if (!data.Vpcs[i].VpcId) continue;
					vpcMap[data.Vpcs[i].VpcId] = [];
				}

				// Now lookup flow logs and map to VPCs
				helpers.cache(cache, ec2, 'describeFlowLogs', function(flErr, flData) {

					if (flErr || !flData || !flData.FlowLogs) {
						console.log(flErr);
						results.push({
							status: 3,
							message: 'Unable to query for flow logs',
							region: region
						});

						return rcb();
					}

					for (f in flData.FlowLogs) {
						if (flData.FlowLogs[f].ResourceId &&
							vpcMap[flData.FlowLogs[f].ResourceId]) {
							vpcMap[flData.FlowLogs[f].ResourceId].push(flData.FlowLogs[f]);
						}
					}

					// Loop through VPCs and add results
					for (v in vpcMap) {
						if (!vpcMap[v].length) {
							results.push({
								status: 1,
								message: 'VPC flow logs are not enabled',
								region: region,
								resource: v
							});
						} else {
							var activeLogs = false;

							for (f in vpcMap[v]) {
								if (vpcMap[v][f].FlowLogStatus == 'ACTIVE') {
									activeLogs = true;
									break;
								}
							}

							if (activeLogs) {
								results.push({
									status: 0,
									message: 'VPC flow logs are enabled',
									region: region,
									resource: v
								});
							} else {
								results.push({
									status: 1,
									message: 'VPC flow logs are enabled, but not active',
									region: region,
									resource: v
								});
							}
						}
					}

					rcb();
				});
			});
		}, function(){
			callback(null, results);
		});
	}
};
