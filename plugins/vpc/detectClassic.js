var AWS = require('aws-sdk');
var async = require('async');

function getPluginInfo() {
	return {
		title: 'Detect EC2 Classic',
		query: 'detectClassic',
		category: 'VPC',
		aws_service: 'VPC',
		description: 'Ensures AWS VPC is being used instead of EC2 Classic',
		more_info: 'VPCs are the latest and more secure method of launching AWS resources. EC2 Classic should not be used.',
		link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html',
		tests: {
			classicInstances: {
				title: 'Detect EC2 Classic Instances',
				description: 'Ensures AWS VPC is being used for instances instead of EC2 Classic',
				recommendedAction: 'Migrate instances from EC2 Classic to VPC',
				results: []
			}
		}
	}
};

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,

	run: function(AWSConfig, callback) {
		var ec2 = new AWS.EC2(AWSConfig);
		var pluginInfo = getPluginInfo();

		ec2.describeInstances({}, function(err, data){
			if (err || !data || !data.Reservations) {
				pluginInfo.tests.classicInstances.results.push({
					status: 3,
					message: 'Unable to query for instances'
				});

				return callback(null, pluginInfo);
			}

			// Perform checks for establishing if MFA token is enabled
			if (!data.Reservations.length) {
				pluginInfo.tests.classicInstances.results.push({
					status: 0,
					message: 'No instances found'
				});

				return callback(null, pluginInfo);
			}

			for (i in data.Reservations) {
				for (j in data.Reservations[i].Instances) {
					// Find the instance name if possible
					var instanceName = ' ';
					if (data.Reservations[i].Instances[j].Tags && data.Reservations[i].Instances[j].Tags.length) {
						for (k in data.Reservations[i].Instances[j].Tags) {
							if (data.Reservations[i].Instances[j].Tags[k].Key === 'Name' && data.Reservations[i].Instances[j].Tags[k].Value && data.Reservations[i].Instances[j].Tags[k].Value.length) {
								instanceName = ' (' + data.Reservations[i].Instances[j].Tags[k].Value + ') ';
							}
						}
					}

					if (!data.Reservations[i].Instances[j].NetworkInterfaces || !data.Reservations[i].Instances[j].NetworkInterfaces.length) {
						// Network interfaces are only listed when the instance is in a VPC
						// Not having interfaces indicates the instance is in classic
						pluginInfo.tests.classicInstances.results.push({
							status: 1,
							message: 'Instance: ' + data.Reservations[i].Instances[j].InstanceId + instanceName + 'is not in a VPC'
						});
					} else {
						pluginInfo.tests.classicInstances.results.push({
							status: 0,
							message: 'Instance: ' + data.Reservations[i].Instances[j].InstanceId + instanceName + 'is in a VPC'
						});
					}
				}
			}

			callback(null, pluginInfo);
		});
	}
};