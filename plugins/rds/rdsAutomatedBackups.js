var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Automated Backups',
	category: 'RDS',
	description: 'Ensures automated backups are enabled for RDS instances',
	more_info: 'AWS provides a simple method of backing up RDS instances at a regular interval. This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
	recommended_action: 'Enable automated backups for the RDS instance',

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

					if (data.DBInstances[i].BackupRetentionPeriod && data.DBInstances[i].BackupRetentionPeriod > 6) {
						results.push({
							status: 0,
							message: 'Automated backups are enabled with sufficient retention (' + data.DBInstances[i].BackupRetentionPeriod + ' days)',
							resource: dbResource,
							region: region
						});
					} else if (data.DBInstances[i].BackupRetentionPeriod) {
						results.push({
							status: 1,
							message: 'Automated backups are enabled but do not have sufficient retention (' + data.DBInstances[i].BackupRetentionPeriod + ' days)',
							resource: dbResource,
							region: region
						});
					} else {
						results.push({
							status: 2,
							message: 'Automated backups are not enabled',
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
