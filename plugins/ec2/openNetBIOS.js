var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Open NetBIOS',
	category: 'EC2',
	description: 'Determine if UDP port 137 or 138 for NetBIOS is open to the public',
	more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as NetBIOS should be restricted to known IP addresses.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
	recommended_action: 'Restrict UDP ports 137 and 138 to known IP addresses',
	apis: ['EC2:describeSecurityGroups'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var ports = {
			'udp': [137, 138]
		};

		var service = 'NetBIOS';

		async.each(helpers.regions.ec2, function(region, rcb){
			var describeSecurityGroups = helpers.addSource(cache, source,
				['ec2', 'describeSecurityGroups', region]);

			if (!describeSecurityGroups) return rcb();

			if (describeSecurityGroups.err || !describeSecurityGroups.data) {
				helpers.addResult(results, 3, 'Unable to query for security groups', region);
				return rcb();
			}

			if (!describeSecurityGroups.data.length) {
				helpers.addResult(results, 0, 'No security groups present', region);
				return rcb();
			}

			var found = false;

			for (i in describeSecurityGroups.data) {
				for (j in describeSecurityGroups.data[i].IpPermissions) {
					var permission = describeSecurityGroups.data[i].IpPermissions[j];

					for (k in permission.IpRanges) {
						var range = permission.IpRanges[k];

						if (range.CidrIp === '0.0.0.0/0' && ports[permission.IpProtocol]) {
							for (port in ports[permission.IpProtocol]) {
								if (permission.FromPort <= port && permission.ToPort >= port) {
									found = true;

									var resource = 'arn:aws:ec2:' + region + ':' + 
													describeSecurityGroups.data[i].OwnerId +
													':security-group/' + describeSecurityGroups.data[i].GroupId;

									helpers.addResult(results, 2,
										'Security group: ' + describeSecurityGroups.data[i].GroupId +
										' (' + describeSecurityGroups.data[i].GroupName +
										') has ' + service + ' ' + permission.IpProtocol.toUpperCase() +
										' port ' + port + ' open to 0.0.0.0/0', region,
										resource);
								}
							}
						}
					}
				}
			}

			if (!found) {
				helpers.addResult(results, 0, 'No public open ports found', region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
