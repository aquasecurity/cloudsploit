var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQS Cross Account Access',
    category: 'SQS',
    description: 'Ensures SQS policies allows cross-account access only to trusted account',
    more_info: 'SQS policies should be carefully restricted to prevent publishing or reading from the queue from unexpected sources. Queue policies can be used to limit these privileges.',
    recommended_action: 'Update the SQS policy to prevent access from untrusted external accounts.',
    link: 'http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html',
    apis: ['SQS:listQueues', 'SQS:getQueueAttributes', 'STS:getCallerIdentity'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If SQS queues process this kind of data, ' +
             'ensure that the queue policies do not allow reads by third-party accounts.'
    },
    settings: {
        whitelisted_accounts: {
            name: 'Allowed cross-account role account IDs',
            description: 'Return a failing result if cross-account role contains any account ID other than these account IDs',
            regex: '^[0-9{12}]$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var whitelisted_accounts = settings.whitelisted_accounts || this.settings.whitelisted_accounts.default;
        whitelisted_accounts = whitelisted_accounts.split(',');

        var acctRegion = helpers.defaultRegion(settings);
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
                var crossAccount = false;
                var untrustedAccounts = [];
                var crossAccountActions = [];
                var statements = helpers.normalizePolicyDocument(policy);

                for (var s in statements) {
                    var statement = statements[s];
                    if (!statement.Effect || statement.Effect !== 'Allow' || !statement.Principal) continue;
                    if (helpers.globalPrincipal(statement.Principal)) {
                        if(!statement.Condition ||
                            (statement.Condition.StringEquals && (
                                !statement.Condition.StringEquals['AWS:SourceOwner'] ||
                                statement.Condition.StringEquals['AWS:SourceOwner'] == '*') ||
                            (statement.Condition.ArnEquals && (
                                !statement.Condition.ArnEquals['aws:SourceArn'] ||
                                statement.Condition.ArnEquals['aws:SourceArn'].indexOf(accountId) === -1)))) {
                            for (var a in statement.Action) {
                                if (globalActions.indexOf(statement.Action[a]) === -1) {
                                    globalActions.push(statement.Action[a]);
                                }
                            }
                        }
                    } else {
                        if (helpers.crossAccountPrincipal(statement.Principal, accountId)) {
                            crossAccount = true;
                            var accounts = helpers.extractAccountsFromPrincipal(statement.Principal);
                            
                            if (accounts.length) {
                                accounts.forEach(account => {
                                    if (whitelisted_accounts.indexOf(account) === -1) {
                                        untrustedAccounts.push(account);  
                                    }
                                });

                                for (a in statement.Action) {
                                    if (crossAccountActions.indexOf(statement.Action[a]) === -1) {
                                        crossAccountActions.push(statement.Action[a]);
                                    }
                                }
                            }
                        }
                    }
                }

                if (globalActions.length) {
                    helpers.addResult(results, 2,
                        'The SQS queue policy allows global access to the action(s): ' + globalActions,
                        region, queueArn);
                } else if (crossAccount && !untrustedAccounts.length && crossAccountActions.length) {
                    helpers.addResult(results, 0,
                        'The SQS queue policy allows trusted cross-account access to the action(s): ' + crossAccountActions,
                        region, queueArn);
                }
                else if (crossAccount) {
                    helpers.addResult(results, 2,
                        'The SQS queue policy allows untrusted cross-account access to the action(s): ' + crossAccountActions,
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