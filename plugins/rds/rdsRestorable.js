var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'RDS Restorable',
	category: 'RDS',
	description: 'Ensures RDS instances can be restored to a recent point',
	more_info: 'AWS will maintain a point to which the database can be restored. This point should not drift too far into the past, or else the risk of irrecoverable data loss may occur.',
	link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html',
	recommended_action: 'Ensure the instance is running and configured properly. If the time drifts too far, consider opening a support ticket with AWS.',
	apis: ['RDS:describeDBInstances', 'RDS:describeDBClusters'],
	settings: {
		rds_restorable_fail: {
			name: 'RDS Restorable Time Fail',
			description: 'Return a failing result when RDS restorable time exceeds this number of hours',
			regex: '^[1-9]{1}[0-9]{0,2}$',
			default: 24
		},
		rds_restorable_warn: {
			name: 'RDS Restorable Time Warn',
			description: 'Return a warning result when RDS restorable time exceeds this number of hours',
			regex: '^[1-9]{1}[0-9]{0,2}$',
			default: 6
		}
	},

	run: function(cache, settings, callback) {
		var config = {
			rds_restorable_fail: settings.rds_restorable_fail || this.settings.rds_restorable_fail.default,
			rds_restorable_warn: settings.rds_restorable_warn || this.settings.rds_restorable_warn.default
		};

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		async.each(regions.rds, function(region, rcb){
			var describeDBInstances = helpers.addSource(cache, source,
				['rds', 'describeDBInstances', region]);

			if (!describeDBInstances) return rcb();

			if (describeDBInstances.err || !describeDBInstances.data) {
				helpers.addResult(results, 3,
					'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
				return rcb();
			}

			if (!describeDBInstances.data.length) {
				helpers.addResult(results, 0, 'No RDS instances found', region);
				return rcb();
			}

			var clustersPresent = false;

			for (i in describeDBInstances.data) {
				var db = describeDBInstances.data[i];

				// Aurora databases do not list the restore information in this API call
				if (db.Engine && db.Engine.indexOf('aurora') > -1) {
					clustersPresent = true;
					continue;
				}

				var dbResource = db.DBInstanceArn;

				if (db.LatestRestorableTime) {
					var difference = helpers.functions.daysAgo(db.LatestRestorableTime);
					var returnMsg = 'RDS instance restorable time is ' + difference + ' hours old';

					if (difference > 24) {
						helpers.addResult(results, 2, returnMsg, region, dbResource);
					} else if (difference > 6) {
						helpers.addResult(results, 1, returnMsg, region, dbResource);
					} else {
						helpers.addResult(results, 0, returnMsg, region, dbResource);
					}
				} else if (!db.ReadReplicaSourceDBInstanceIdentifier) {
					// Apply rule to everything else except Read replicas
					helpers.addResult(results, 2, 'RDS instance does not have a restorable time',
						region, dbResource);
				}
			}

			if (!clustersPresent) return rcb();

			var describeDBClusters = helpers.addSource(cache, source,
				['rds', 'describeDBClusters', region]);

			if (!describeDBClusters) return rcb();

			if (describeDBClusters.err || !describeDBClusters.data) {
				helpers.addResult(results, 3,
					'Unable to query for RDS clusters: ' + helpers.addError(describeDBClusters), region);
				return rcb();
			}

			if (!describeDBClusters.data.length) {
				return rcb();
			}

			for (i in describeDBClusters.data) {
				var db = describeDBClusters.data[i];
				var dbResource = db.DBClusterArn;

				if (db.LatestRestorableTime) {
					var difference = helpers.functions.daysAgo(db.LatestRestorableTime);
					var returnMsg = 'RDS cluster restorable time is ' + difference + ' hours old';

					if (difference > config.rds_restorable_fail) {
						helpers.addResult(results, 2, returnMsg, region, dbResource, custom);
					} else if (difference > config.rds_restorable_warn) {
						helpers.addResult(results, 1, returnMsg, region, dbResource, custom);
					} else {
						helpers.addResult(results, 0, returnMsg, region, dbResource, custom);
					}
				} else {
					helpers.addResult(results, 2, 'RDS cluster does not have a restorable time',
						region, dbResource);
				}
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
