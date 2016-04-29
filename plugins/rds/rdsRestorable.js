var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Restorable',
	category: 'RDS',
	description: 'Ensures RDS instances can be restored to a recent point',
	more_info: 'AWS will maintain a point to which the database can be restored. This point should not drift too far into the past, or else the risk of irrecoverable data loss may occur.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html',
	recommended_action: 'Ensure the instance is running and configured properly. If the time drifts too far, consider opening a support ticket with AWS.',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.each(helpers.regions.rds, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var rds = new AWS.RDS(LocalAWSConfig);

			helpers.cache(cache, rds, 'describeDBInstances', function(err, data) {
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

					if (data.DBInstances[i].LatestRestorableTime) {
						var difference = helpers.functions.daysAgo(data.DBInstances[i].LatestRestorableTime);

						var statusObj = {
							status: 0,
							message: 'RDS instance restorable time is ' + difference + ' hours old',
							resource: dbResource,
							region: region
						};

						if (difference > 24) {
							statusObj.status = 2;
						} else if (difference > 6) {
							statusObj.status = 1;
						}

						results.push(statusObj);
					} else {
						results.push({
							status: 2,
							message: 'RDS instance does not have a restorable time',
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
