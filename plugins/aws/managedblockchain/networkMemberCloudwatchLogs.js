var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Managed Blockchain Network Member CloudWatch Logs',
    category: 'Managed Blockchain',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensure that Amazon Managed Blockchain members have CloudWatch logs enabled.',
    more_info: 'Enabling CloudWatch Logs for Amazon Managed Blockchain helps troubleshoot chaincode development, monitor network activity, and identify errors by publishing peer node, chaincode, and certificate authority (CA) logs.',
    link: 'https://docs.aws.amazon.com/managed-blockchain/latest/hyperledger-fabric-dev/monitoring-cloudwatch-logs.html',
    recommended_action: 'Modify Managed Blockchain members to enable CloudWatch Logs',
    apis: ['ManagedBlockchain:listMembers', 'ManagedBlockchain:listNetworks', 'ManagedBlockchain:getMember'],
    realtime_triggers: ['managedblockchain:CreateNetwork', 'managedblockchain:DeleteMember'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.managedblockchain, function(region, rcb){
            var listNetworks = helpers.addSource(cache, source,
                ['managedblockchain', 'listNetworks', region]);

            if (!listNetworks) return rcb();

            if (listNetworks.err || !listNetworks.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Managed Blockchain networks: ${helpers.addError(listNetworks)}`, region);
                return rcb();
            }

            if (!listNetworks.data.length) {
                helpers.addResult(results, 0, 'No Managed Blockchain networks found', region);
                return rcb();
            }

            for (let network of listNetworks.data) {
                if (!network.Id || !network.Arn) continue;
                
                let listMembers = helpers.addSource(cache, source,
                    ['managedblockchain', 'listMembers', region, network.Id]);

                if (!listMembers || listMembers.err || !listMembers.data || !listMembers.data.Members) {
                    helpers.addResult(results, 3,
                        `Unable to query network members: ${helpers.addError(listMembers)}`,
                        region, network.Arn);
                    continue;
                }

                if (!listMembers.data.Members.length) {
                    helpers.addResult(results, 0, 'No network members found', region, network.Arn);
                    continue;
                }

                for (let member of listMembers.data.Members) {
                    if (!member.Id || !member.Arn) continue;

                    let resource = member.Arn;
                    let getMember = helpers.addSource(cache, source,
                        ['managedblockchain', 'getMember', region, member.Id]);
    
                    if (!getMember || getMember.err || !getMember.data || !getMember.data.Member) {
                        helpers.addResult(results, 3,
                            `Unable to query network member: ${helpers.addError(getMember)}`,
                            region, member.Arn);
                        continue;
                    }
                    const getmember = getMember.data.Member

                    if (getmember.LogPublishingConfiguration && getmember.LogPublishingConfiguration.Fabric &&
                        getmember.LogPublishingConfiguration.Fabric.CaLogs && getmember.LogPublishingConfiguration.Fabric.CaLogs.Cloudwatch
                        &&  getmember.LogPublishingConfiguration.Fabric.CaLogs.Cloudwatch.Enabled) {
                            helpers.addResult(results, 0,
                                'Network member has CloudWatch logs enabled',
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                'Network member does not have CloudWatch logs enabled',
                                region, resource);
                        }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
