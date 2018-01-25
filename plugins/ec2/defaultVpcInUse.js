var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Default VPC In Use',
	category: 'EC2',
	description: 'Determines whether the default VPC is being used for launching EC2 instances.',
	more_info: 'The default VPC should not be used in order to avoid launching multiple services in the same network which may not require connectivity. Each application, or network tier, should use its own VPC.',
	link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/default-vpc.html',
	recommended_action: 'Move resources from the default VPC to a new VPC created for that application or resource group.',
	apis: ['EC2:describeVpcs', 'EC2:describeInstances', 'ELB:describeLoadBalancers', 'Lambda:listFunctions', 'RDS:describeDBInstances', 'Redshift:describeClusters'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.vpc, function(region, rcb){
			var describeVpcs = helpers.addSource(cache, source,
				['ec2', 'describeVpcs', region]);

			if (!describeVpcs) return rcb();

			if (describeVpcs.err || !describeVpcs.data) {
				helpers.addResult(results, 3,
					'Unable to query for VPCs: ' + helpers.addError(describeVpcs), region);
				return rcb();
			}

			if (!describeVpcs.data.length) {
				helpers.addResult(results, 0, 'No VPCs present', region);
				return rcb();
			}

			// Find the default VPC
			var defaultVpcId;

			for (v in describeVpcs.data) {
				var vpc = describeVpcs.data[v];
				if (vpc.IsDefault) defaultVpcId = vpc.VpcId;
			}

			if (!defaultVpcId) {
				helpers.addResult(results, 0, 'No default VPC present', region);
				return rcb();
			}

			// Find count of each resource
			var numInstances = 0;
			var numDBs = 0;
			var numFunctions = 0;
			var numElbs = 0;
			var numRedshift = 0;

			// Look for EC2 instances
			var describeInstances = helpers.addSource(cache, source,
				['ec2', 'describeInstances', region]);

			if (!describeInstances || !describeInstances.data || describeInstances.err) {
				helpers.addResult(results, 3, 'Unable to query for EC2 instances: ' + helpers.addError(describeInstances), region);
			} else if (describeInstances.data.length) {
				// Count instances in VPC
				for (i in describeInstances.data) {
					for (j in describeInstances.data[i].Instances) {
						if (describeInstances.data[i].Instances[j].VpcId &&
							describeInstances.data[i].Instances[j].VpcId == defaultVpcId) {
							numInstances += 1;
						}
					}
				}
			}

			// Look for ELBs
			var describeLoadBalancers = helpers.addSource(cache, source,
				['elb', 'describeLoadBalancers', region]);

			if (!describeLoadBalancers || !describeLoadBalancers.data || describeLoadBalancers.err) {
				helpers.addResult(results, 3, 'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
			} else if (describeLoadBalancers.data.length) {
				// Count ELBs in VPC
				for (i in describeLoadBalancers.data) {
					if (describeLoadBalancers.data[i].VPCId &&
						describeLoadBalancers.data[i].VPCId == defaultVpcId) {
						numElbs += 1;
					}
				}
			}

			// Look for Lambda functions

			// Skip Lambda if in unsupported region
			if (helpers.regions.lambda.indexOf(region) > -1) {
				var listFunctions = helpers.addSource(cache, source,
					['lambda', 'listFunctions', region]);

				if (!listFunctions || !listFunctions.data || listFunctions.err) {
					helpers.addResult(results, 3, 'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
				} else if (listFunctions.data.length) {
					// Count functions in VPC
					for (i in listFunctions.data) {
						if (listFunctions.data[i].VpcConfig &&
							listFunctions.data[i].VpcConfig.VpcId &&
							listFunctions.data[i].VpcConfig.VpcId == defaultVpcId) {
							numFunctions += 1;
						}
					}
				}
			}

			// Look for RDS instances
			var describeDBInstances = helpers.addSource(cache, source,
				['rds', 'describeDBInstances', region]);

			if (!describeDBInstances || !describeDBInstances.data || describeDBInstances.err) {
				helpers.addResult(results, 3, 'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
			} else if (describeDBInstances.data.length) {
				// Count RDS instances in VPC
				for (i in describeDBInstances.data) {
					if (describeDBInstances.data[i].DBSubnetGroup &&
						describeDBInstances.data[i].DBSubnetGroup.VpcId &&
						describeDBInstances.data[i].DBSubnetGroup.VpcId == defaultVpcId) {
						numDBs += 1;
					}
				}
			}

			// Look for Redshift instances
			var describeClusters = helpers.addSource(cache, source,
				['redshift', 'describeClusters', region]);

			if (!describeClusters || !describeClusters.data || describeClusters.err) {
				helpers.addResult(results, 3, 'Unable to query for Redshift instances: ' + helpers.addError(describeClusters), region);
			} else if (describeClusters.data.length) {
				// Count Redshift instances in VPC
				for (i in describeClusters.data) {
					if (describeClusters.data[i].VpcId &&
						describeClusters.data[i].VpcId == defaultVpcId) {
						numRedshift += 1;
					}
				}
			}

			if (!numInstances && !numElbs &&
				!numFunctions && !numDBs && !numRedshift) {
				helpers.addResult(results, 0, 'Default VPC is not in use', region);
				return rcb();
			} else {
				var numStr = numInstances + ' EC2 instance' + (numInstances === 1 ? '' : 's') + '; ' +
							 numElbs + ' ELB' + (numElbs === 1 ? '' : 's') + '; ' +
							 numFunctions + ' Lambda function' + (numFunctions === 1 ? '' : 's') + '; ' +
							 numDBs + ' RDS instance' + (numDBs === 1 ? '' : 's') + '; ' +
							 numRedshift + ' Redshift cluster' + (numRedshift === 1 ? '' : 's');
				helpers.addResult(results, 2, 'Default VPC is in use: ' + numStr, region);
				return rcb();
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
