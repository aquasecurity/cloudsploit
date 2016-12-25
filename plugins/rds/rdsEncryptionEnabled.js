var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Encryption Enabled',
	category: 'RDS',
	description: 'Ensures at-rest encryption is setup for RDS instances',
	more_info: 'AWS provides at-read encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
	recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		async.eachLimit(helpers.regions.rds, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var rds = new AWS.RDS(LocalAWSConfig);

			helpers.cache(cache, rds, 'describeDBInstances', function(err, data) {
				if (includeSource) source[region] = {error: err, data: data};
				
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

					// Encryption enabled
					if (data.DBInstances[i].StorageEncrypted) {
						results.push({
							status: 0,
							message: 'Encryption at rest is enabled',
							resource: dbResource,
							region: region
						});
					} else {
						results.push({
							status: 1,
							message: 'Encryption at rest is not enabled',
							resource: dbResource,
							region: region
						});
					}
				}
				
				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};
