var AWS = require('aws-sdk');
var async = require('async');
var regions = require('./../../regions.json');

function getPluginInfo() {
	return {
		title: 'Account Limits',
		query: 'accountLimits',
		category: 'EC2',
		description: 'Determine if the number of resources is close to the AWS per-account limit',
		tests: {
			elasticIpLimit: {
				title: 'Elastic IP Limit',
				description: 'Determine if the number of allocated EIPs is close to the AWS per-account limit',
				more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
				recommended_action: 'Contact AWS support to increase the number of EIPs available',
				results: []
			},
			vpcElasticIpLimit: {
				title: 'VPC Elastic IP Limit',
				description: 'Determine if the number of allocated VPC EIPs is close to the AWS per-account limit',
				more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
				recommended_action: 'Contact AWS support to increase the number of EIPs available',
				results: []
			},
			instanceLimit: {
				title: 'Instance Limit',
				description: 'Determine if the number of EC2 instances is close to the AWS per-account limit',
				more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
				recommended_action: 'Contact AWS support to increase the number of instances available',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var pluginInfo = getPluginInfo();

		async.each(regions, function(region, rcb){
			AWSConfig.region = region;
			var ec2 = new AWS.EC2(AWSConfig);

			// Get the account attributes
			ec2.describeAccountAttributes({}, function(err, data){
				if (err) {
					pluginInfo.tests.elasticIpLimit.results.push({
						status: 3,
						message: 'Unable to query for account limits',
						region: region
					});
					pluginInfo.tests.vpcElasticIpLimit.results.push({
						status: 3,
						message: 'Unable to query for account limits',
						region: region
					});
					pluginInfo.tests.instanceLimit.results.push({
						status: 3,
						message: 'Unable to query for account limits',
						region: region
					});

					return rcb();
				}

				// Default limits to override
				var limits = {
					'max-instances': 20,
					'max-elastic-ips': 5,
					'vpc-max-elastic-ips': 5
				};

				// Loop through response to assign custom limits
				if (data && data.AccountAttributes && data.AccountAttributes.length) {
					for (i in data.AccountAttributes) {
						if (limits[data.AccountAttributes[i].AttributeName]) {
							limits[data.AccountAttributes[i].AttributeName] = data.AccountAttributes[i].AttributeValues[0].AttributeValue;
						}
					}
					
					// Now call APIs to determine actual usage
					async.parallel([
						function(cb) {
							// Determine elastic IP usage
							ec2.describeAddresses({}, function(err, data){
								if (err) {
									pluginInfo.tests.elasticIpLimit.results.push({
										status: 3,
										message: 'Unable to query for Elastic IP limit',
										region: region
									});
									pluginInfo.tests.vpcElasticIpLimit.results.push({
										status: 3,
										message: 'Unable to query for VPC Elastic IP limit',
										region: region
									});

									return cb();
								}

								if (data && data.Addresses) {
									if (!data.Addresses.length) {
										pluginInfo.tests.elasticIpLimit.results.push({
											status: 0,
											message: 'No Elastic IPs found',
											region: region
										});
										pluginInfo.tests.vpcElasticIpLimit.results.push({
											status: 0,
											message: 'No VPC Elastic IPs found',
											region: region
										});

										return cb();
									}

									// If EIPs exist, determine type of each
									var eips = 0;
									var vpcEips = 0;
									for (i in data.Addresses) {
										if (data.Addresses[i].Domain === 'vpc') {
											vpcEips++;
										} else {
											eips++;
										}
									}

									var returnMsg = {
										status: 0,
										message: 'Account contains ' + eips + ' of ' + limits['max-elastic-ips'] + ' available Elastic IPs',
										region: region
									};

									if (eips === 0) {
										returnMsg.message = 'No Elastic IPs found';
									} else if (eips === limits['max-elastic-ips'] - 1) {
										returnMsg.status = 1;
									} else if (eips >= limits['max-elastic-ips']) {
										returnMsg.status = 2;
									}

									pluginInfo.tests.elasticIpLimit.results.push(returnMsg);

									var returnMsgVpc = {
										status: 0,
										message: 'Account contains ' + vpcEips + ' of ' + limits['vpc-max-elastic-ips'] + ' available VPC Elastic IPs',
										region: region
									};

									if (vpcEips === 0) {
										returnMsgVpc.message = 'No VPC Elastic IPs found'
									} else if (vpcEips === limits['vpc-max-elastic-ips'] - 1) {
										returnMsgVpc.status = 1;
									} else if (vpcEips >= limits['vpc-max-elastic-ips']) {
										returnMsgVpc.status = 2;
									}

									pluginInfo.tests.vpcElasticIpLimit.results.push(returnMsgVpc);
									
									return cb();
								}

								// No data or addresses map
								pluginInfo.tests.elasticIpLimit.results.push({
									status: 3,
									message: 'Unable to query for Elastic IP limit',
									region: region
								});
								pluginInfo.tests.vpcElasticIpLimit.results.push({
									status: 3,
									message: 'Unable to query for VPC Elastic IP limit',
									region: region
								});

								return cb();
							});
						},

						function(cb) {
							ec2.describeInstances(function(err, data){
								if (err || !data || !data.Reservations) {
									pluginInfo.tests.instanceLimit.results.push({
										status: 3,
										message: 'Unable to query for instances',
										region: region
									});

									return cb();
								}

								var returnMsgIl = {
									status: 0,
									message: 'Account contains ' + data.Reservations.length + ' of ' + limits['max-instances'] + ' available instances',
									region: region
								};

								if (data.Reservations.length === limits['max-instances'] - 3) {
									returnMsgIl.status = 1;
								} else if (data.Reservations.length >= limits['max-instances'] - 2) {
									returnMsgIl.status = 2;
								}

								pluginInfo.tests.instanceLimit.results.push(returnMsgIl);

								cb();
							})
						}
					], function(){
						// All tests are finished
						rcb();
					});
				} else {
					var returnMsgErr = {
						status: 3,
						message: 'Unable to query for account limits',
						region: region
					};

					pluginInfo.tests.elasticIpLimit.results.push(returnMsgErr);
					pluginInfo.tests.vpcElasticIpLimit.results.push(returnMsgErr);
					pluginInfo.tests.instanceLimit.results.push(returnMsgErr);

					rcb();
				}
			});
		}, function(){
			return callback(null, pluginInfo);
		});
	}
};