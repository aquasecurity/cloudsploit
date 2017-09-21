var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Open All Ports Protocols',
	category: 'EC2',
	description: 'Determine if security group has all ports or protocols open to the public',
	more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
	recommended_action: 'Modify the security group to specify a specific port and protocol to allow.',
	apis: ['EC2:describeSecurityGroups'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

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

			var found = false;
			var groups = describeSecurityGroups.data;

			for (g in groups) {
				var strings = [];
				var resource = 'arn:aws:ec2:' + region + ':' +
							   groups[g].OwnerId + ':security-group/' +
							   groups[g].GroupId;

				for (p in groups[g].IpPermissions) {
					var permission = groups[g].IpPermissions[p];

					for (k in permission.IpRanges) {
						var range = permission.IpRanges[k];

						if (range.CidrIp === '0.0.0.0/0') {
							if (!permission.FromPort && (!permission.ToPort || permission.ToPort === 65535)) {
								var string = 'all ports open to 0.0.0.0/0';
								if (strings.indexOf(string) === -1) strings.push(string);
								found = true;
							}

							if (permission.IpProtocol === '-1') {
								var string = 'all protocols open to 0.0.0.0/0';
								if (strings.indexOf(string) === -1) strings.push(string);
								found = true;
							}
						}
					}

					for (k in permission.Ipv6Ranges) {
						var range = permission.Ipv6Ranges[k];

						if (range.CidrIpv6 === '::/0') {
							if (!permission.FromPort && (!permission.ToPort || permission.ToPort === 65535)) {
								var string = 'all ports open to ::/0';
								if (strings.indexOf(string) === -1) strings.push(string);
								found = true;
							}

							if (permission.IpProtocol === '-1') {
								var string = 'all protocols open to ::/0';
								if (strings.indexOf(string) === -1) strings.push(string);
								found = true;
							}
						}
					}
				}

				if (strings.length) {
					helpers.addResult(results, 2,
						'Security group: ' + groups[g].GroupId +
						' (' + groups[g].GroupName +
						') has ' + strings.join(' and '), region,
						resource);
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
