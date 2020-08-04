var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Logging Enabled',
    category: 'EKS',
    description: 'Ensures all EKS cluster logs are being sent to CloudWatch',
    more_info: 'EKS supports routing of cluster event and audit logs to CloudWatch, including control plane logs. All logs should be sent to CloudWatch for security analysis.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html',
    recommended_action: 'Enable all EKS cluster logs to be sent to CloudWatch with proper log retention limits.',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity'],
    remediation_description: 'EKS logging will be enabled for all supported services.',
    remediation_min_version: '202006221808',
    apis_remediate: ['EKS:listClusters', 'EKS:describeCluster'],
    actions: {remediate: ['EKS:updateClusterConfig'], rollback: ['EKS:updateClusterConfig']},
    permissions: {remediate: ['eks:UpdateClusterConfig'], rollback: ['eks:UpdateClusterConfig']},

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.eks, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['eks', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if(listClusters.data.length === 0){
                helpers.addResult(results, 0, 'No EKS clusters present', region);
                return rcb();
            }

            for (var c in listClusters.data) {
                var clusterName = listClusters.data[c];
                var describeCluster = helpers.addSource(cache, source,
                    ['eks', 'describeCluster', region, clusterName]);

                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;

                if (!describeCluster || describeCluster.err || !describeCluster.data) {
                    helpers.addResult(
                        results, 3,
                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
                        region, arn);
                    continue;
                }

                if (describeCluster.data.cluster &&
                    describeCluster.data.cluster.logging &&
                    describeCluster.data.cluster.logging.clusterLogging &&
                    describeCluster.data.cluster.logging.clusterLogging.length) {
                    
                    var logEnabled = [];
                    var logDisabled = [];

                    for (var l in describeCluster.data.cluster.logging.clusterLogging) {
                        var group = describeCluster.data.cluster.logging.clusterLogging[l];

                        for (var t in group.types) {
                            var groupName = group.types[t];
                            if (group.enabled && logEnabled.indexOf(groupName) === -1) {
                                logEnabled.push(groupName);
                            } else if (logDisabled.indexOf(groupName) === -1) {
                                logDisabled.push(groupName);
                            }
                        }
                    }

                    if (logEnabled.length && logDisabled.length) {
                        helpers.addResult(results, 2,
                            'EKS cluster logging is enabled for: ' + logEnabled.join(', ') + ' logs but disabled for: ' + logDisabled.join(', ') + ' logs',
                            region, arn);
                    } else if (logDisabled.length) {
                        helpers.addResult(results, 2,
                            'EKS cluster logging is disabled for: ' + logDisabled.join(', ') + ' logs',
                            region, arn);
                    } else {
                        helpers.addResult(results, 0,
                            'EKS cluster logging is enabled for: ' + logEnabled.join(', ') + ' logs',
                            region, arn);
                    }
                } else {
                    helpers.addResult(results, 2, 'EKS cluster logging is not enabled', region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'eksLoggingEnabled';
        var clusterNameArr = resource.split('/');
        var clusterArnArr = resource.split(':');
        var clusterName = clusterNameArr[clusterNameArr.length - 2];
        if (!clusterName) return callback('could not parse cluster name');
        config.region = clusterArnArr[clusterArnArr.length - 3];
        if (!config.region) return callback('could not parse region');


        if (!clusterName) callback('could not get cluster name');

        var params = {};
        params = {
            'name': clusterName,
            'logging': {
                'clusterLogging': [{
                    enabled: true,
                    types: [
                        'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'
                    ]
                }]
            }
        };

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'logging': 'Disabled',
            'name': clusterName
        };

        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enabled',
                'name': clusterName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
