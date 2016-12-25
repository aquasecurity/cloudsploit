var async = require('async');
var AWS = require('aws-sdk');
var helpers = require('../../helpers');

module.exports = {
	title: 'Email DKIM Enabled',
	category: 'SES',
	description: 'Ensures DomainKeys Identified Mail (DKIM) is enabled for domains and addresses in SES.',
	more_info: 'DKIM is a security feature that allows recipients of an email to veriy that the sender domain has authorized the message and that it has not been spoofed.',
	recommended_action: 'Enable DKIM for all domains and addresses in all regions used to send email through SES.',
	link: 'http://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		// AWS limits this API call to 1 per second, perform serially
		async.eachLimit(helpers.regions.ses, 1, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ses = new AWS.SES(LocalAWSConfig);

			var regionCallback = function() {
				setTimeout(function(){
					return rcb();
				}, 1000);
			};

			if (includeSource) source['listIdentities'] = {};
			if (includeSource) source['getIdentityDkimAttributes'] = {};

			ses.listIdentities({IdentityType: 'Domain'}, function(listErr, listData) {
				if (includeSource) source['listIdentities'][region] = {error: listErr, data: listData};

				if (listErr || !listData || !listData.Identities) {
					results.push({
						status: 3,
						message: 'Unable to query for SES identities',
						region: region
					});
					return regionCallback();
				}

				if (!listData.Identities.length) {
					results.push({
						status: 0,
						message: 'No SES identities found',
						region: region
					});
					return regionCallback();
				}

				// Determine the DKIM status
				ses.getIdentityDkimAttributes({Identities: listData.Identities}, function(getErr, getData){
					if (includeSource) source['getIdentityDkimAttributes'][region] = {error: getErr, data: getData};

					if (getErr || !getData || !getData.DkimAttributes) {
						results.push({
							status: 3,
							message: 'Unable to get SES DKIM attributes',
							region: region
						});
						return regionCallback();
					}

					for (i in getData.DkimAttributes) {
						var identity = getData.DkimAttributes[i];

						if (!identity.DkimEnabled) {
							results.push({
								status: 2,
								message: 'DKIM is not enabled',
								region: region,
								resource: i
							});
						} else if (identity.DkimVerificationStatus !== 'Success') {
							results.push({
								status: 1,
								message: 'DKIM is enabled, but not configured properly',
								region: region,
								resource: i
							});
						} else {
							results.push({
								status: 0,
								message: 'DKIM is enabled and configured properly',
								region: region,
								resource: i
							});
						}
					}

					return regionCallback();
				});
			});
		}, function(){
			return callback(null, results, source);
		});
	}
};