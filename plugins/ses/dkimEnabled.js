var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Email DKIM Enabled',
	category: 'SES',
	description: 'Ensures DomainKeys Identified Mail (DKIM) is enabled for domains and addresses in SES.',
	more_info: 'DKIM is a security feature that allows recipients of an email to veriy that the sender domain has authorized the message and that it has not been spoofed.',
	recommended_action: 'Enable DKIM for all domains and addresses in all regions used to send email through SES.',
	link: 'http://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html',
	apis: ['SES:listIdentities', 'SES:getIdentityDkimAttributes'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ses, function(region, rcb){
			var listIdentities = helpers.addSource(cache, source,
				['ses', 'listIdentities', region]);

			if (!listIdentities) return rcb();

			if (listIdentities.err || !listIdentities.data) {
				helpers.addResult(results, 3,
					'Unable to query for SES identities: ' + helpers.addError(listIdentities), region);
				return rcb();
			}

			if (!listIdentities.data.length) {
				helpers.addResult(results, 0, 'No SES identities found', region);
				return rcb();
			}

			var getIdentityDkimAttributes = helpers.addSource(cache, source,
				['ses', 'getIdentityDkimAttributes', region]);

			if (!getIdentityDkimAttributes ||
				getIdentityDkimAttributes.err ||
				!getIdentityDkimAttributes.data) {
				helpers.addResult(results, 3,
					'Unable to get SES DKIM attributes: ' + helpers.addError(getIdentityDkimAttributes), region);
				return rcb();
			}

			for (i in getIdentityDkimAttributes.data.DkimAttributes) {
				var identity = getIdentityDkimAttributes.data.DkimAttributes[i];

				if (!identity.DkimEnabled) {
					helpers.addResult(results, 2, 'DKIM is not enabled', region, i);
				} else if (identity.DkimVerificationStatus !== 'Success') {
					helpers.addResult(results, 1,
						'DKIM is enabled, but not configured properly', region, i);
				} else {
					helpers.addResult(results, 0,
						'DKIM is enabled and configured properly', region, i);
				}
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};