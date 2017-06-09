var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'CloudTrail File Validation',
	category: 'CloudTrail',
	description: 'Ensures CloudTrail file validation is enabled for all regions within an account',
	more_info: 'CloudTrail file validation is essentially a hash of the file which can be used to ensure its integrity in the case of an account compromise.',
	recommended_action: 'Enable CloudTrail file validation for all regions',
	link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html',
	apis: ['CloudTrail:describeTrails'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.cloudtrail, function(region, rcb){
			var describeTrails = helpers.addSource(cache, source,
				['cloudtrail', 'describeTrails', region]);

			if (!describeTrails) return rcb();

			if (describeTrails.err || !describeTrails.data) {
				helpers.addResult(results, 3,
					'Unable to query for CloudTrail file validation status: ' + helpers.addError(describeTrails), region);
				return rcb();
			}

			if (!describeTrails.data.length) {
				helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
			} else if (describeTrails.data[0]) {
				for (t in describeTrails.data) {
					if (!describeTrails.data[t].LogFileValidationEnabled) {
						helpers.addResult(results, 2, 'CloudTrail log file validation is not enabled',
							region, describeTrails.data[t].TrailARN)
					} else {
						helpers.addResult(results, 0, 'CloudTrail log file validation is enabled',
							region, describeTrails.data[t].TrailARN)
					}
				}
			} else {
				helpers.addResult(results, 2, 'CloudTrail is enabled but is not properly configured', region);
			}
			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};