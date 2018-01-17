// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Default VPC In Use',
	category: 'EC2',
	description: 'Determines whether the default VPC is being used for launching EC2 instances.',
	more_info: 'The default VPC should not be used in order to avoid launching multiple \
		services in the same network which may not require connectivity. \
		Each application, or network tier, should use its own VPC.',
	link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/default-vpc.html',
	recommended_action: 'Move resources from the default VPC to a new VPC created \
		for that application or resource group.',
	apis: ['EC2:describeVpcs', 'EC2:describeVpcInstances'],
	compliance: {
        hipaa: 'VPC Flow Logs provide a detailed traffic log of a VPC network ' +
        		'containing HIPAA data. Flow Logs should be enabled to satisfy ' +
        		'the audit controls of the HIPAA framework.'
    },

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.flowlogs, function(region, rcb){
			var describeVpcs = helpers.addSource(cache, source,
				['ec2', 'describeVpcs', region]);

			if (!describeVpcs) return rcb();

			if (describeVpcs.err || !describeVpcs.data) {
				helpers.addResult(results, 3,
					'Unable to query for VPCs: ' + helpers.addError(describeVpcs), region);
				return rcb();
			}

			if (!describeVpcs.data.length) {
				helpers.addResult(results, 0, 'No VPCs found', region);
				return rcb();
			}

			var default_vpc = [];

			// loop through for all vpcs and list all vpc which tagged as
			// default
			for(vpc of describeVpcs.data) {
				if(vpc.Tags.length) {
					for(tag of vpc.Tags) {
						if (tag.Key == 'Name' && tag.Value == 'default') {
							default_vpc.push(vpc)
						}
					}
				}
			}

			if (!default_vpc.length) {
				helpers.addResult(results, 0, 'No Default VPCs found', region);
				return rcb();
			}

			// loop through all default vpc
			for(vpc of default_vpc) {

				// fetch ec2 instances for given vpc
				var ec2instances = helpers.addSource(cache, source,
					['ec2', 'describeVpcInstances', region, vpc.VpcId]);

				// if any ec2 instances found in default vpc raise warning
				if (ec2instances.data.Reservations.length) {
					message = vpc.VpcId + ' used by ec2 instances'
					helpers.addResult(results, 2, 'Default VPC in use', region, message);
				}
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
