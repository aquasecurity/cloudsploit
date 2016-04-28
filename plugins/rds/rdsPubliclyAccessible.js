var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Publicly Accessible',
	category: 'RDS',
	description: 'Ensures RDS instances are not launched into the public cloud',
	more_info: 'Unless there is a specific business requirement, RDS instances should not have a public endpoint and should be accessed from within a VPC only.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html',
	recommended_action: 'Remove the public endpoint from the RDS instance',

	run: function(AWSConfig, callback) {
		var results = [];

		async.each(helpers.regions.rds, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var rds = new AWS.RDS(LocalAWSConfig);

			helpers.cache(rds, 'describeDBInstances', function(err, data) {
				if (err || !data || !data.DBInstances) {
					results.push({
						status: 3,
						message: 'Unable to query for RDS instances',
						region: region
					});

					return rcb();
				}

				if (!data.DBInstances.length) {
					results.push({
						status: 0,
						message: 'No RDS instances found',
						region: region
					});

					return rcb();
				}

				for (i in data.DBInstances) {
					// For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
					var dbResource = (data.DBInstances[i].Endpoint && data.DBInstances[i].Endpoint.Address) ? data.DBInstances[i].Endpoint.Address : data.DBInstances[i].DBInstanceIdentifier;

					if (data.DBInstances[i].PubliclyAccessible) {
						results.push({
							status: 1,
							message: 'RDS instance is publicly accessible',
							resource: dbResource,
							region: region
						});
					} else {
						results.push({
							status: 0,
							message: 'RDS instance is not publicly accessible',
							resource: dbResource,
							region: region
						});
					}
				}
				
				rcb();
			});
		}, function(){
			callback(null, results);
		});
	}
};
