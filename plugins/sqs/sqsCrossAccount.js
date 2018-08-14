var async = require('async');
var helpers = require('../../helpers');

function globalPrincipal(principal) {
	if (typeof principal === 'string' && principal === '*') {
		return true;
	}

	var awsPrincipals = principal.AWS;
	if(!Array.isArray(awsPrincipals)) {
		awsPrincipals = [awsPrincipals];
	}

	if (awsPrincipals.indexOf('*') > -1 ||
		awsPrincipals.indexOf('arn:aws:iam::*') > -1) {
		return true;
	}

	return false;
}

function crossAccountPrincipal(principal, accountId) {
	if (typeof principal === 'string' &&
	    /^[0-9]{12}$/.test(principal) &&
	    principal !== accountId) {
		return true;
	}

	var awsPrincipals = principal.AWS;
	if(!Array.isArray(awsPrincipals)) {
		awsPrincipals = [awsPrincipals];
	}

	for (a in awsPrincipals) {
		if (/^arn:aws:iam::[0-9]{12}.*/.test(awsPrincipals[a]) &&
			awsPrincipals[a].indexOf(accountId) === -1) {
			return true;
		}
	}

	return false;
}

module.exports = {
	title: 'SQS Cross Account Access',
	category: 'SQS',
	description: 'Ensures SQS policies disallow cross-account access',
	more_info: 'SQS policies should be carefully restricted to prevent publishing or reading from the queue from unexpected sources. Queue policies can be used to limit these privileges.',
	recommended_action: 'Update the SQS policy to prevent access from external accounts.',
	link: 'http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html',
	apis: ['SQS:listQueues', 'SQS:getQueueAttributes', 'STS:getCallerIdentity'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};
		var regions = helpers.regions(settings.govcloud);

		var acctRegion = settings.govcloud ? 'us-gov-west-1' : 'us-east-1';
		var accountId = helpers.addSource(cache, source,
			['sts', 'getCallerIdentity', acctRegion, 'data']);

		async.each(regions.sqs, function(region, rcb){
			var listQueues = helpers.addSource(cache, source,
				['sqs', 'listQueues', region]);

			if (!listQueues) return rcb();

			if (listQueues.err) {
				helpers.addResult(results, 3,
					'Unable to query for SQS queues: ' + helpers.addError(listQueues), region);
				return rcb();
			}

			if (!listQueues.data || !listQueues.data.length) {
				helpers.addResult(results, 0, 'No SQS queues found', region);
				return rcb();
			}

			async.each(listQueues.data, function(queue, cb){

				var getQueueAttributes = helpers.addSource(cache, source,
					['sqs', 'getQueueAttributes', region, queue]);

				if (!getQueueAttributes ||
					(!getQueueAttributes.err && !getQueueAttributes.data)) return cb();

				if (getQueueAttributes.err ||
					!getQueueAttributes.data ||
					!getQueueAttributes.data.Attributes ||
					!getQueueAttributes.data.Attributes.QueueArn) {
					helpers.addResult(results, 3,
						'Unable to query SQS for queue: ' + queue,
						region);

					return cb();
				}

				var queueArn = getQueueAttributes.data.Attributes.QueueArn;

				if (!getQueueAttributes.data.Attributes.Policy) {
					helpers.addResult(results, 0,
						'The SQS queue does not use a custom policy',
						region, queueArn);
					return cb();
				}

				try {
					var policy = JSON.parse(getQueueAttributes.data.Attributes.Policy);
				} catch (e) {
					helpers.addResult(results, 3,
						'The SQS queue policy could not be parsed to valid JSON.',
						region, queueArn);

					return cb();
				}

				var globalActions = [];
				var crossAccountActions = [];

				var statements = helpers.normalizePolicyDocument(policy);

				for (s in statements) {
					var statement = statements[s];
					if (!statement.Effect || statement.Effect !== 'Allow') continue;
					if (!statement.Principal) continue;

					if (globalPrincipal(statement.Principal)) {
						if(!statement.Condition ||
							(statement.Condition.StringEquals && (
								!statement.Condition.StringEquals['AWS:SourceOwner'] ||
								statement.Condition.StringEquals['AWS:SourceOwner'] == '*') ||
							(statement.Condition.ArnEquals && (
								!statement.Condition.ArnEquals['aws:SourceArn'] ||
								statement.Condition.ArnEquals['aws:SourceArn'].indexOf(accountId) === -1)))
							) {

							for (a in statement.Action) {
								if (globalActions.indexOf(statement.Action[a]) === -1) {
									globalActions.push(statement.Action[a]);
								}
							}
						}
					} else {
						if (crossAccountPrincipal(statement.Principal, accountId)) {
							// Another account
							for (a in statement.Action) {
								if (crossAccountActions.indexOf(statement.Action[a]) === -1) {
									crossAccountActions.push(statement.Action[a]);
								}
							}
						}
					}
				}

				if (globalActions.length) {
					helpers.addResult(results, 2,
						'The SQS queue policy allows global access to the action(s): ' + globalActions,
						region, queueArn);
				} else if (crossAccountActions.length) {
					helpers.addResult(results, 2,
						'The SQS queue policy allows cross-account access to the action(s): ' + crossAccountActions,
						region, queueArn);
				} else {
					helpers.addResult(results, 0,
						'The SQS queue policy does not allow global or cross-account access.',
						region, queueArn);
				}

				cb();
			}, function(){
				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};