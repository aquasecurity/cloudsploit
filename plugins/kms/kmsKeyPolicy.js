var async = require('async');
var helpers = require('../../helpers');
module.exports = {
	title: 'KMS Key Policy',
	category: 'KMS',
	description: 'Validates the KMS key policy to ensure least-privilege access.',
	more_info: 'KMS key policies should be designed to limit the number of users who can perform encrypt and decrypt operations. Each application should use its own key to avoid over exposure.',
	recommended_action: 'Modify the KMS key policy to remove any wildcards and limit the number of users and roles that can perform encrypt and decrypt operations using the key.',
	link: 'http://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html',
	apis: ['KMS:listKeys', 'STS:getCallerIdentity', 'KMS:getKeyPolicy'],
	settings: {
		kms_key_policy_max_user_count: {
			name: 'KMS Key Policy Max User Count',
			description: 'Return a failing result when KMS key policies contain more than this many trusted users',
			regex: '^[1-9]{1}[0-9]{0,3}$',
			default: 10
		}
	},

	run: function(cache, settings, callback) {
		var config = {
			kms_key_policy_max_user_count: settings.kms_key_policy_max_user_count || this.settings.kms_key_policy_max_user_count.default
		};

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		var acctRegion = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
		var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
		
		const const_wildcard = '*'

		async.each(regions.kms, function(region, rcb){
			var listKeys = helpers.addSource(cache, source,
					['kms', 'listKeys', region]);

			if (!listKeys) return rcb();

			if (listKeys.err || !listKeys.data){
				helpers.addResult(results, 3,
					'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
				return rcb();
			}

			if (!listKeys.data.length){
				helpers.addResult(results, 0, 'No KMS keys found', region);
				return rcb();
			}

			async.each(listKeys.data, function(kmsKey, kcb){

				var getKeyPolicy = helpers.addSource(cache, source,
					['kms', 'getKeyPolicy', region, kmsKey.KeyId]);

				if (!getKeyPolicy || getKeyPolicy.err || !getKeyPolicy.data){
					helpers.addResult(results, 3,
						'Unable to get key policy: ' + helpers.addError(getKeyPolicy),
						region, kmsKey.KeyArn);
					return kcb();
				}
				
				var found = false;
				var wildcardTrusted = 0;
				var thirdPartyTrusted = 0;

				var statements = getKeyPolicy.data.Statement;
				var totalUsers = [];

				for (s in statements) {
					var statement = statements[s];

					if (!statement.Principal || !statement.Effect ||
						statement.Effect !== 'Allow') continue;

					var principal = statement.Principal;

					if (!principal.AWS) continue;

					if (typeof principal.AWS === 'string') {
						principal.AWS = [principal.AWS];
					}

					if (!Array.isArray(principal.AWS)) continue;

					totalUsers = totalUsers.concat(principal.AWS);

					var conditionalCaller = null;

					if (statement.Condition &&
						statement.Condition.StringEquals &&
						statement.Condition.StringEquals['kms:CallerAccount']) {
						conditionalCaller = statement.Condition.StringEquals['kms:CallerAccount'];
					}

					// Check for wildcards without condition
					if (principal.AWS.indexOf('*') > -1 && !conditionalCaller) {
						wildcardTrusted += 1;
					} else if (conditionalCaller && conditionalCaller !== accountId) {
						thirdPartyTrusted += 1;
					} else if (!conditionalCaller) {
						for (u in principal.AWS) {
							if (principal.AWS[u] !== '*' && principal.AWS[u].indexOf(accountId) === -1) {
								thirdPartyTrusted += 1;
							}
						}
					}
				}

				if (totalUsers.length > config.kms_key_policy_max_user_count) {
					found = true;
					helpers.addResult(results, 2, 'Key trusts ' + totalUsers.length +
						' users', region, kmsKey.KeyArn, custom);
				}

				if (thirdPartyTrusted) {
				    found = true;
				    helpers.addResult(results, 1, 'Key trusts ' + thirdPartyTrusted +
				    	' third parties', region, kmsKey.KeyArn, custom);
				}

				if (wildcardTrusted) {
					found = true;
					helpers.addResult(results, 1, 'Key trusts ' + wildcardTrusted +
						' principals with wildcards', region, kmsKey.KeyArn, custom);
				}
				
				if (!found){
					helpers.addResult(results, 0, 'Key policy is sufficient', region, kmsKey.KeyArn, custom);
				}
				
				kcb();
			}, function(){
				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};
