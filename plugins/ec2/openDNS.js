var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Open DNS',
	category: 'EC2',
	description: 'Determine if TCP or UDP port 53 for DNS is open to the public',
	more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as DNS should be restricted to known IP addresses.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
	recommended_action: 'Restrict TCP and UDP port 53 to known IP addresses',
	apis: ['EC2:describeSecurityGroups'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		var ports = {
			'udp': [53],
			'tcp': [53]
		};

		var service = 'DNS';

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

			helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results);

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
