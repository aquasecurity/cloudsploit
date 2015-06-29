var pluginInfo = {
	title: 'Elastic IP Limit',
	query: 'elasticIpLimit',
	category: 'EC2',
	aws_service: 'EC2',
	description: 'Determine if the number of allocated EIPs is close to the AWS per-account limit',
	more_info: 'AWS limits accounts to 5 EIPs due to scarcity of IPv4 addresses',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
	tests: {
		elasticIpLimit: {
			title: 'Elastic IP Limit',
			description: 'Determine if the number of allocated EIPs is close to the AWS per-account limit',
			recommendedAction: 'Contact AWS support to increase the number of EIPs available',
			results: []
		}
	}
};

module.exports = {
	title: pluginInfo.title,
	query: pluginInfo.query,
	category: pluginInfo.category,
	description: pluginInfo.description,
	more_info: pluginInfo.more_info,
	link: pluginInfo.link,

	run: function(AWS, callback) {
		var ec2 = new AWS.EC2();

		ec2.describeAddresses({}, function(err, data){
			if (err) {
				callback(err);
				return;
			}

			// Perform checks for establishing if MFA token is enabled
			if (data && data.Addresses) {
				if (!data.Addresses.length) {
					pluginInfo.tests.elasticIpLimit.results.push({
						status: 0,
						message: 'No Elastic IPs found'
					});
				} else if (data.Addresses.length === 4) {
					pluginInfo.tests.elasticIpLimit.results.push({
						status: 1,
						message: 'Account contains 4 of 5 available Elastic IPs'
					});
				} else if (data.Addresses.length === 5) {
					pluginInfo.tests.elasticIpLimit.results.push({
						status: 2,
						message: 'Account contains 5 of 5 available Elastic IPs'
					});
				} else {
					pluginInfo.tests.elasticIpLimit.results.push({
						status: 0,
						message: 'Account contains ' + data.Addresses.length + ' of 5 available Elastic IPs'
					});
				}
				callback(null, pluginInfo);
			} else {
				callback('unexpected return data');
				return;
			}
		});
	}
};