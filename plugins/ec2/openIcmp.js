var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Open ICMP Access',
	category: 'EC2',
	description: 'Remove ICMP access or limit it to known IP blocks.',
	more_info: 'ICMP should not be allowed from global IP addresses in security groups.',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html',
	recommended_action: 'Remove ICMP access or limit it to known IP blocks.',
	apis: ['EC2:describeSecurityGroups'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		var service = 'icmp';

		async.each(helpers.regions.ec2, function(region, rcb){
			var describeSecurityGroups = helpers.addSource(cache, source,
				['ec2', 'describeSecurityGroups', region]);

			if (!describeSecurityGroups) return rcb();

			if (describeSecurityGroups.err || !describeSecurityGroups.data) {
				helpers.addResult(results, 3,
					'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
				return rcb();
			}

			if (!describeSecurityGroups.data.length) {
				helpers.addResult(results, 0, 'No security groups present', region);
				return rcb();
			}
			var groups = describeSecurityGroups.data

			// loop through all groups
			for (g in groups) {
				var resource = 'arn:aws:ec2:' + region + ':' +
					   groups[g].OwnerId + ':security-group/' +
					   groups[g].GroupId;

				// loop through all its ip permission for protocol ICMP
				for (p in groups[g].IpPermissions) {
					var permission = groups[g].IpPermissions[p];
					// check if IpProtocal is icmp
					if (permission.IpProtocol == service){
						// now check for ipv4
						for (k in permission.IpRanges) {
							var range = permission.IpRanges[k];
							if (range.CidrIp === '0.0.0.0/0' || range.CidrIp ==='::/0') {
								helpers.addResult(results, 2,
								'Security group: ' + groups[g].GroupId +
								' has ' + permission.IpProtocol.toUpperCase() +
								' open to 0.0.0.0/0', region, resource);
							}
						}

						// now check for ipv6
						for (k in permission.Ipv6Ranges) {
							var range = permission.Ipv6Ranges[k];
							if (range.CidrIp === '0.0.0.0/0' || range.CidrIp ==='::/0') {
								helpers.addResult(results, 2,
								'Security group: ' + groups[g].GroupId +
								' has ' + permission.IpProtocol.toUpperCase() +
								' open to 0.0.0.0/0', region, resource);
							}
						}
					}
				}
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
