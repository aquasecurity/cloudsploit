var AWS = require('aws-sdk');
var async = require('async');
var regions = require(__dirname + '/../../regions.json');

function getPluginInfo() {
	return {
		title: 'Database Security',
		query: 'databaseSecurity',
		category: 'RDS',
		description: 'Ensures databases are properly configured in RDS',
		tests: {
			rdsEncryptionEnabled: {
				title: 'RDS Encryption Enabled',
				description: 'Ensures at-rest encryption is setup for RDS instances',
				more_info: 'AWS provides at-read encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.',
				link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
				recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.',
				results: []
			},
			rdsAutomatedBackups: {
				title: 'RDS Automated Backups',
				description: 'Ensures automated backups are enabled for RDS instances',
				more_info: 'AWS provides a simple method of backing up RDS instances at a regular interval. This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.',
				link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
				recommended_action: 'Enable automated backups for the RDS instance',
				results: []
			},
			rdsPubliclyAccessible: {
				title: 'RDS Publicly Accessible',
				description: 'Ensures RDS instances are not launched into the public cloud',
				more_info: 'Unless there is a specific business requirement, RDS instances should not have a public endpoint and should be accessed from within a VPC only.',
				link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html',
				recommended_action: 'Remove the public endpoint from the RDS instance',
				results: []
			},
			rdsRestorable: {
				title: 'RDS Restorable',
				description: 'Ensures RDS instances can be restored to a recent point',
				more_info: 'AWS will maintain a point to which the database can be restored. This point should not drift too far into the past, or else the risk of irrecoverable data loss may occur.',
				link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html',
				recommended_action: 'Ensure the instance is running and configured properly. If the time drifts too far, consider opening a support ticket with AWS.',
				results: []
			}
		}
	}
};

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var pluginInfo = getPluginInfo();

		var now = new Date();	// used for restore time check

		async.each(regions, function(region, rcb){
			AWSConfig.region = region;
			var rds = new AWS.RDS(AWSConfig);

			rds.describeDBInstances({}, function(err, data){
				if (err || !data) {
					var statusObj = {
						status: 3,
						message: 'Unable to query for RDS instances',
						region: region
					};

					pluginInfo.tests.rdsEncryptionEnabled.results.push(statusObj);
					pluginInfo.tests.rdsAutomatedBackups.results.push(statusObj);
					pluginInfo.tests.rdsPubliclyAccessible.results.push(statusObj);
					pluginInfo.tests.rdsRestorable.results.push(statusObj);

					return rcb();
				}

				if (!data.DBInstances || !data.DBInstances.length) {
					var statusObj = {
						status: 0,
						message: 'No RDS instances found',
						region: region
					};

					pluginInfo.tests.rdsEncryptionEnabled.results.push(statusObj);
					pluginInfo.tests.rdsAutomatedBackups.results.push(statusObj);
					pluginInfo.tests.rdsPubliclyAccessible.results.push(statusObj);
					pluginInfo.tests.rdsRestorable.results.push(statusObj);

					return rcb();
				}

				for (i in data.DBInstances) {
					// For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
					var dbResource = (data.DBInstances[i].Endpoint && data.DBInstances[i].Endpoint.Address) ? data.DBInstances[i].Endpoint.Address : data.DBInstances[i].DBInstanceIdentifier;

					// Automated backups
					if (data.DBInstances[i].BackupRetentionPeriod && data.DBInstances[i].BackupRetentionPeriod > 6) {
						pluginInfo.tests.rdsAutomatedBackups.results.push({
							status: 0,
							message: 'Automated backups are enabled with sufficient retention (' + data.DBInstances[i].BackupRetentionPeriod + ' days)',
							resource: dbResource,
							region: region
						});
					} else if (data.DBInstances[i].BackupRetentionPeriod) {
						pluginInfo.tests.rdsAutomatedBackups.results.push({
							status: 1,
							message: 'Automated backups are enabled but do not have sufficient retention (' + data.DBInstances[i].BackupRetentionPeriod + ' days)',
							resource: dbResource,
							region: region
						});
					} else {
						pluginInfo.tests.rdsAutomatedBackups.results.push({
							status: 2,
							message: 'Automated backups are not enabled',
							resource: dbResource,
							region: region
						});
					}

					// Encryption enabled
					if (data.DBInstances[i].StorageEncrypted) {
						pluginInfo.tests.rdsEncryptionEnabled.results.push({
							status: 0,
							message: 'Encryption at rest is enabled',
							resource: dbResource,
							region: region
						});
					} else {
						pluginInfo.tests.rdsEncryptionEnabled.results.push({
							status: 1,
							message: 'Encryption at rest is not enabled',
							resource: dbResource,
							region: region
						});
					}

					// Publicly accessible
					if (data.DBInstances[i].PubliclyAccessible) {
						pluginInfo.tests.rdsPubliclyAccessible.results.push({
							status: 1,
							message: 'RDS instance is publicly accessible',
							resource: dbResource,
							region: region
						});
					} else {
						pluginInfo.tests.rdsPubliclyAccessible.results.push({
							status: 0,
							message: 'RDS instance is not publicly accessible',
							resource: dbResource,
							region: region
						});
					}

					// Latest restorable time
					if (data.DBInstances[i].LatestRestorableTime) {
						var then = new Date(data.DBInstances[i].LatestRestorableTime);
						var difference = Math.floor((now - then) / 1000 / 60 / 60);	// number of hours difference

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

						pluginInfo.tests.rdsRestorable.results.push(statusObj);
					} else {
						pluginInfo.tests.rdsRestorable.results.push({
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
			callback(null, pluginInfo);
		});
	}
};
