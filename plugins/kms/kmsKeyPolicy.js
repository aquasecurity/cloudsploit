var async = require('async');
var helpers = require('../../helpers');
module.exports = {
	title: 'KMS Key Policy',
	category: 'KMS',
	description: 'Detects KMS keys that are scheduled for deletion',
	more_info: 'Detects KMS Keys policy for users',
	recommended_action: '',
	link: 'https://docs.aws.amazon.com/kms/latest/developerguide/overview.html',
	apis: ['KMS:listKeys', 'STS:getCallerIdentity', 'KMS:getKeyPolicy'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', 'us-east-1', 'data']);
		const maxUserCount = 10;
		const const_wildcard = '*'

		async.each(helpers.regions.kms, function(region, rcb){
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
						'Unable to get key policy: ' + helpers.addError(describeKey),
						region, kmsKey.KeyArn);
					return kcb();
				}
				var found = false;

				for(stmnt of getKeyPolicy.data.Statement){
					allowed_users = stmnt.Principal.AWS;
					switch(allowed_users.constructor.name){
                        case 'String':
                            // if it is string then it have only has only one user
                            // check if account id is same or not if not raise warning
                            if (allowed_users.indexOf(accountId) == -1){
                            	found = true;
                                helpers.addResult(results, 1, 'User account doesn\'t match', region, kmsKey.KeyArn);
                            }
                            break;
                        case 'Array':
                            // if it is an array
                            // first check for if it has more the max user
                            if (allowed_users.length > maxUserCount){
                            	found = true;
                                helpers.addResult(results, 1, 'Key has more than '+ maxUserCount +
                                	' users', region, kmsKey.KeyArn);
                            }
                            // the loop through it and check for same user
                            for (iam_arn of allowed_users) {
                                if (iam_arn.indexOf(accountId) == -1){
                                	found = true;
                                    helpers.addResult(results, 1, 'User account doesn\'t match', region, kmsKey.KeyArn);
                                }
                            }
                            break;
                        default:
                            helpers.addResult(results, 3, 'Unable to parse getKeyPolicy', region);
                    }
				}
				if (!found){
					helpers.addResult(results, 0, 'Principal are trusted', region, kmsKey.KeyArn);
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
