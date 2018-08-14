var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Elastic IP Limit',
	category: 'EC2',
	description: 'Determine if the number of allocated EIPs is close to the AWS per-account limit',
	more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
	recommended_action: 'Contact AWS support to increase the number of EIPs available',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
	apis: ['EC2:describeAccountAttributes', 'EC2:describeAddresses'],
	settings: {
		elastic_ip_percentage_fail: {
			name: 'Elastic IP Percentage Fail',
			description: 'Return a failing result when consumed elastic IPs equals or exceeds this percentage',
			regex: '^(100|[1-9][0-9]?)$',
			default: 90
		},
		elastic_ip_percentage_warn: {
			name: 'Elastic IP Percentage Warn',
			description: 'Return a warning result when consumed elastic IPs equals or exceeds this percentage',
			regex: '^(100|[1-9][0-9]?)$',
			default: 75
		}
	},

	run: function(cache, settings, callback) {
		var config = {
			elastic_ip_percentage_fail: settings.elastic_ip_percentage_fail || this.settings.elastic_ip_percentage_fail.default,
			elastic_ip_percentage_warn: settings.elastic_ip_percentage_warn || this.settings.elastic_ip_percentage_warn.default
		};

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		async.each(regions.ec2, function(region, rcb){
			var describeAccountAttributes = helpers.addSource(cache, source,
				['ec2', 'describeAccountAttributes', region]);

			if (!describeAccountAttributes) return rcb();

			if (describeAccountAttributes.err || !describeAccountAttributes.data) {
				helpers.addResult(results, 3,
					'Unable to query for account limits: ' + helpers.addError(describeAccountAttributes), region);
				return rcb();
			}

			var limits = {
				'max-elastic-ips': 5
			};

			// Loop through response to assign custom limits
			for (i in describeAccountAttributes.data) {
				if (limits[describeAccountAttributes.data[i].AttributeName]) {
					limits[describeAccountAttributes.data[i].AttributeName] = describeAccountAttributes.data[i].AttributeValues[0].AttributeValue;
				}
			}

			var describeAddresses = helpers.addSource(cache, source,
				['ec2', 'describeAddresses', region]);

			if (!describeAddresses) return rcb();

			if (describeAddresses.err || !describeAddresses.data) {
				helpers.addResult(results, 3,
					'Unable to describe addresses for Elastic IP limit: ' + helpers.addError(describeAddresses), region);
				return rcb();
			}
			
			if (!describeAddresses.data.length) {
				helpers.addResult(results, 0, 'No Elastic IPs found', region);
				return rcb();
			}

			// If EIPs exist, determine type of each
			var eips = 0;

			for (i in describeAddresses.data) {
				if (describeAddresses.data[i].Domain !== 'vpc') { eips++; }
			}

			var percentage = Math.ceil((eips / limits['max-elastic-ips'])*100);
			var returnMsg = 'Account contains ' + eips + ' of ' + limits['max-elastic-ips'] + ' (' + percentage + '%) available Elastic IPs';

			if (percentage >= config.elastic_ip_percentage_fail) {
				helpers.addResult(results, 2, returnMsg, region, null, custom);
			} else if (percentage >= config.elastic_ip_percentage_warn) {
				helpers.addResult(results, 1, returnMsg, region, null, custom);
			} else {
				helpers.addResult(results, 0, returnMsg, region, null, custom);
			}
			
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};