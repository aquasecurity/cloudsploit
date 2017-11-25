var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'SQS Cross Account Access',
	category: 'SQS',
	description: 'Ensures SQS policies disallow cross-account access',
	more_info: 'SQS policies should be carefully restricted to prevent publishing or reading from the queue from unexpected sources. Queue policies can be used to limit these privileges.',
	recommended_action: 'Update the SQS policy to prevent access from external accounts.',
	link: 'http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html',
	apis: ['SQS:listQueues', 'SQS:getQueueAttributes'],

	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.sqs, function(region, rcb){
			var listQueues = helpers.addSource(cache, source,
				['sqs', 'listQueues', region]);

			if (!listQueues) return rcb();

			if (listQueues.err || !listQueues.data) {
				helpers.addResult(results, 3,
					'Unable to query for SQS queues: ' + helpers.addError(listQueues), region);
				return rcb();
			}

			if (!listQueues.data.length) {
				helpers.addResult(results, 0, 'No SQS queues found', region);
				return rcb();
			}

			async.each(listQueues.data, function(queue, cb){
				
				var getQueueAttributes = helpers.addSource(cache, source,
					['sqs', 'getQueueAttributes', region, queue]);

				if (!getQueueAttributes ||
					(!getQueueAttributes.err && !getQueueAttributes.data)) return cb();

				if (getQueueAttributes.err || !getQueueAttributes.data) {
					helpers.addResult(results, 3,
						'Unable to query SQS queue for queue: ' + queue + ': ' + helpers.addError(getQueueAttributes),
						region);

					return cb();
				}

				if (!getQueueAttributes.data.Attributes ||
					!getQueueAttributes.data.Attributes.Policy) {
					helpers.addResult(results, 3,
						'The SQS queue does not have a policy attached: ' + queue,
						region);

					return cb();
				}

				var queueArn = getQueueAttributes.data.Attributes.QueueArn || null;

				try {
					var policy = JSON.parse(getQueueAttributes.data.Attributes.Policy);
				} catch (e) {
					helpers.addResult(results, 3,
						'The SQS queue policy is not valid JSON.',
						region, queueArn);

					return cb();
				}

				var actions = [];

				var statements = helpers.normalizePolicyDocument(policy);

				for (s in statements) {
					var statement = statements[s];

					if (statement.Effect && statement.Effect == 'Allow' &&
						statement.Principal && statement.Principal.AWS &&
						(statement.Principal.AWS === '*' ||
						 statement.Principal.AWS === 'arn:aws:iam::*') &&
						(!statement.Condition || !statement.Condition.StringEquals ||
						 !statement.Condition.StringEquals['AWS:SourceOwner'] ||
						 statement.Condition.StringEquals['AWS:SourceOwner'] == '*')) {
						
						for (a in statement.Action) {
							if (actions.indexOf(statement.Action[a]) === -1) {
								actions.push(statement.Action[a]);
							}
						}
					}
				}

				if (actions.length) {
					helpers.addResult(results, 2,
						'The SQS queue policy allows global access to the action(s): ' + actions,
						region, queueArn);
				} else {
					helpers.addResult(results, 0,
						'The SQS queue policy does not allow global access.',
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