var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Config Service Enabled',
	category: 'ConfigService',
	description: 'Ensures the AWS Config Service is enabled to detect changes to account resources',
	more_info: 'The AWS Config Service tracks changes to a number of resources in an AWS account and is invaluable in determining how account changes affect other resources and in recovery in the event of an account intrusion or accidental configuration change.',
	recommended_action: 'Enable the AWS Config Service for all regions and resources in an account. Ensure that it is properly recording and delivering logs.',
	link: 'https://aws.amazon.com/config/details/',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		var globalServicesMonitored = false;

		async.eachLimit(helpers.regions.configservice, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var configservice = new AWS.ConfigService(LocalAWSConfig);

			async.parallel([
				// See if global services are monitored
				function(pcb) {
					if (includeSource) source['describeConfigurationRecorders'] = {};

					helpers.cache(cache, configservice, 'describeConfigurationRecorders', function(err, data) {
						if (includeSource) source['describeConfigurationRecorders'][region] = {error: err, data: data};

						if (data &&
							data.ConfigurationRecorders &&
							data.ConfigurationRecorders[0] &&
							data.ConfigurationRecorders[0].recordingGroup &&
							data.ConfigurationRecorders[0].recordingGroup.includeGlobalResourceTypes) {
							globalServicesMonitored = true;
						}

						pcb();
					});
				},
				// Look up API response that returns whether the config service is recording
				function(pcb) {
					if (includeSource) source['describeConfigurationRecorderStatus'] = {};

					helpers.cache(cache, configservice, 'describeConfigurationRecorderStatus', function(err, data) {
						if (includeSource) source['describeConfigurationRecorderStatus'][region] = {error: err, data: data};

						if (err || !data || !data.ConfigurationRecordersStatus) {
							results.push({
								status: 3,
								message: 'Unable to query for Config Service status',
								region: region
							});
							return pcb();
						}

						if (data.ConfigurationRecordersStatus[0]) {
							if (data.ConfigurationRecordersStatus[0].recording) {
								if (data.ConfigurationRecordersStatus[0].lastStatus &&
									(data.ConfigurationRecordersStatus[0].lastStatus == 'SUCCESS' ||
									 data.ConfigurationRecordersStatus[0].lastStatus == 'PENDING')) {
									results.push({
										status: 0,
										message: 'Config Service is configured, recording, and delivering properly',
										region: region
									});
								} else {
									results.push({
										status: 1,
										message: 'Config Service is configured, and recording, but not delivering properly',
										region: region
									});
								}
							} else {
								results.push({
									status: 2,
									message: 'Config Service is configured but not recording',
									region: region
								});
							}

							return pcb();
						}

						results.push({
							status: 2,
							message: 'Config Service is not configured',
							region: region
						});

						pcb();
					});
				}
			], function(){
				rcb();
			});
		}, function(){
			if (!globalServicesMonitored) {
				results.push({
					status: 2,
					message: 'Config Service is not monitoring global services',
					region: 'global'
				});
			} else {
				results.push({
					status: 0,
					message: 'Config Service is monitoring global services',
					region: 'global'
				});
			}

			return callback(null, results, source);
		});
	}
};