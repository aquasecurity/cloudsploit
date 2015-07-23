var AWS = require('aws-sdk');
var async = require('async');

var regions = require(__dirname + '/../../regions.json');

function getPluginInfo() {
	return {
		title: 'Detect EC2 Classic',
		query: 'detectClassic',
		category: 'VPC',
		description: 'Ensures AWS VPC is being used instead of EC2 Classic',
		tests: {
			classicInstances: {
				title: 'Detect EC2 Classic Instances',
				description: 'Ensures AWS VPC is being used for instances instead of EC2 Classic',
				more_info: 'VPCs are the latest and more secure method of launching AWS resources. EC2 Classic should not be used.',
				link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html',
				recommended_action: 'Migrate instances from EC2 Classic to VPC',
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
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var pluginInfo = getPluginInfo();

		var params = {
			Filters: [
				{
					Name: 'instance-state-name',
					Values: [
						'pending',
						'running',
						'shutting-down',
						'stopping',
						'stopped'
					]
				}
			]
		};

		async.each(regions, function(region, rcb){
			AWSConfig.region = region;
			var ec2 = new AWS.EC2(AWSConfig);

			ec2.describeInstances(params, function(err, data){
				if (err || !data || !data.Reservations) {
					console.log(err);
					pluginInfo.tests.classicInstances.results.push({
						status: 3,
						message: 'Unable to query for instances',
						region: region
					});

					return rcb();
				}

				// Perform checks for establishing if MFA token is enabled
				if (!data.Reservations.length) {
					pluginInfo.tests.classicInstances.results.push({
						status: 0,
						message: 'No instances found',
						region: region
					});

					return rcb();
				}

				var inVpc = 0;
				var notInVpc = 0;

				for (i in data.Reservations) {
					for (j in data.Reservations[i].Instances) {
						if (!data.Reservations[i].Instances[j].NetworkInterfaces || !data.Reservations[i].Instances[j].NetworkInterfaces.length) {
							// Network interfaces are only listed when the instance is in a VPC
							// Not having interfaces indicates the instance is in classic
							notInVpc+=1;
						} else {
							inVpc+=1;
						}
					}
				}

				if (notInVpc) {
					pluginInfo.tests.classicInstances.results.push({
						status: 1,
						message: 'There are ' + notInVpc + ' instances in EC2-Classic',
						region: region
					});
				} else if (inVpc) {
					pluginInfo.tests.classicInstances.results.push({
						status: 0,
						message: 'There are ' + inVpc + ' instances in a VPC',
						region: region
					});
				} else {
					pluginInfo.tests.classicInstances.results.push({
						status: 0,
						message: 'No instances found',
						region: region
					});
				}

				rcb();
			});
		}, function(){
			callback(null, pluginInfo);
		});
	}
};
