var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Instance vCPU On-Demand Based Limits',
    category: 'EC2',
    description: 'Determine if the number of EC2 On-Demand instances is close to the regional vCPU based limit.',
    more_info: 'AWS limits accounts to certain numbers of resources per region. Exceeding those limits could prevent resources from launching.',
    link: 'https://aws.amazon.com/ec2/faqs/#EC2_On-Demand_Instance_limits',
    recommended_action: 'EC2 automatically increases On Demand Instance limits based on usage, limit increases can be requested via the Limits Page on Amazon EC2 console, the EC2 service page on the Service Quotas console, or the Service Quotas API/CLI.',
    apis: ['EC2:describeAccountAttributes', 'EC2:describeInstances', 'ServiceQuotas:listServiceQuotas'],
    settings: {
        instance_limit_percentage_fail: {
            name: 'Instance Limit Percentage Fail',
            description: 'Return a failing result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        instance_limit_percentage_warn: {
            name: 'Instance Limit Percentage Warn',
            description: 'Return a warning result when utilized instances equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_limit_percentage_fail: settings.instance_limit_percentage_fail || this.settings.instance_limit_percentage_fail.default,
            instance_limit_percentage_warn: settings.instance_limit_percentage_warn || this.settings.instance_limit_percentage_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var limits = {
            'max-instances': 20
        };

        function checkLegacyRegion(describeInstances, region, rcb){
            var describeAccountAttributes = helpers.addSource(cache, source,
                ['ec2', 'describeAccountAttributes', region]);

            if (!describeAccountAttributes || describeAccountAttributes.err || !describeAccountAttributes.data || !describeAccountAttributes.data.length) {
                helpers.addResult(results, 3,
                    'Unable to query for account limits: ' + helpers.addError(describeAccountAttributes) + '. Default limit of ' + limits['max-instances'] + ' will be used.', region);
            } else {
                // Loop through response to assign custom limits
                for (var i in describeAccountAttributes.data) {
                    if (limits[describeAccountAttributes.data[i].AttributeName]) {
                        limits[describeAccountAttributes.data[i].AttributeName] = describeAccountAttributes.data[i].AttributeValues[0].AttributeValue;
                    }
                }
            }

            var ec2Instances = 0;

            for (var instances in describeInstances.data) {
                ec2Instances += describeInstances.data[instances].Instances.length;
            }

            var percentage = Math.ceil((ec2Instances / limits['max-instances'])*100);
            var returnMsg = 'Account contains ' + ec2Instances + ' of ' + limits['max-instances'] + ' (' + percentage + '%) available instances';

            if (percentage >= config.instance_limit_percentage_fail) {
                helpers.addResult(results, 2, returnMsg, region, null, custom);
            } else if (percentage >= config.instance_limit_percentage_warn) {
                helpers.addResult(results, 1, returnMsg, region, null, custom);
            } else {
                helpers.addResult(results, 0, returnMsg, region, null, custom);
            }

            rcb();
        }

        function checkVcpusLimits(describeInstances, region, rcb){
            var describeServiceQuotas = helpers.addSource(cache, source,
                ['servicequotas', 'listServiceQuotas', region]);

            if (!describeServiceQuotas || describeServiceQuotas.err || !describeServiceQuotas.data || !describeServiceQuotas.data.length) {
                helpers.addResult(results, 3,
                    'Unable to query for service quotas: ' + helpers.addError(describeServiceQuotas), region);
                return rcb();
            }

            var instanceMap = {
                instanceType: {},
                cores: {},
                threads: {},
                vcpus: {},
                groupVcpus: {},
                spot: {},
                limit: {},
                limitUsage: {},
                limitType: {},
                quotaName: {},
                groupInstanceTypes: {}
            };

            var onDemandServiceQuotas = describeServiceQuotas.data.filter(sq => {
                if (sq.QuotaName &&
                    sq.QuotaName.includes('On-Demand') &&
                    sq.QuotaName.includes('instances')) {
                    return sq;
                }
            });

            if (onDemandServiceQuotas &&
                onDemandServiceQuotas.length>0) {
                for (var sq in onDemandServiceQuotas) {
                    var serviceQuota = onDemandServiceQuotas[sq];
                    var instanceTypeName = serviceQuota.QuotaName.replace('Running On-Demand ', '').replace(' instances', '').toLowerCase();
                    var instanceType;
                    if (instanceTypeName.indexOf('standard') > -1) {
                        var instanceTypes = instanceTypeName.replace('standard (', '').replace(')', '').replace(/ /g, '').split(',');
                        instanceTypes.forEach((it) => {
                            instanceMap.limit[it] = serviceQuota.Value;
                            instanceMap.limitType[it] = 'standard';
                            instanceMap.quotaName[it] = serviceQuota.QuotaName;
                            instanceMap.groupInstanceTypes[it] = instanceTypes;
                        });
                    } else {
                        instanceType = instanceTypeName;
                        instanceMap.limit[instanceType] = serviceQuota.Value;
                        instanceMap.limitType[instanceType] = 'other';
                        instanceMap.quotaName[instanceType] = serviceQuota.QuotaName;
                    }
                }
            } else {
                helpers.addResult(results, 3,
                    'Unable to query on-demand service quotas: ' + helpers.addError(describeServiceQuotas), region);
                return rcb();
            }

            describeInstances.data.forEach((instances) => {
                instances.Instances.forEach((i) => {
                    var instanceType = i.InstanceType.substring(0, 1);
                    var coreCount = i.CpuOptions.CoreCount;
                    var threadsPerCore = i.CpuOptions.ThreadsPerCore;

                    instanceMap.instanceType[instanceType] = instanceType;

                    var currentCoreCount = (instanceMap.cores[instanceType] ? parseInt(instanceMap.cores[instanceType]) : 0);
                    instanceMap.cores[instanceType] = currentCoreCount + coreCount;

                    var currentThreadsPerCore = (instanceMap.threads[instanceType] ? parseInt(instanceMap.threads[instanceType]) : 0);
                    instanceMap.threads[instanceType] = currentThreadsPerCore + threadsPerCore;

                    instanceMap.vcpus[instanceType] = instanceMap.cores[instanceType] * instanceMap.threads[instanceType];

                    if (instanceMap.groupInstanceTypes[instanceType]) {
                        if (instanceMap.groupInstanceTypes[instanceType].indexOf(instanceType)<0) {
                            var percentage = Math.ceil(instanceMap.vcpus[instanceType] / instanceMap.limit[instanceType] * 100);
                            instanceMap.limitUsage[instanceType] = percentage;
                        } else if (instanceMap.groupInstanceTypes[instanceType].indexOf(instanceType)>-1) {
                            instanceMap.groupVcpus[instanceType] = instanceMap.vcpus[instanceType];
                        }
                    }
                });
            });

            var totalGroupVcpus = Object.values(instanceMap.groupVcpus).reduce(function(acc, val) { return acc + val; }, 0);

            for (const it in instanceMap.instanceType) {
                if (instanceMap.groupInstanceTypes[it]) {
                    instanceMap.groupVcpus[it] = totalGroupVcpus;
                }
            }

            for (const it in instanceMap.instanceType) {
                var percentage;
                if (instanceMap.groupInstanceTypes[it]) {
                    percentage = Math.ceil(instanceMap.groupVcpus[it] / instanceMap.limit[it] * 100);
                } else {
                    percentage = Math.ceil(instanceMap.vcpus[it] / instanceMap.limit[it] * 100);
                }
                instanceMap.limitUsage[it] = percentage;
            }

            var ec2Vcpus = 0;
            var ec2VcpusLimit = 0;
            var ec2VcpusLimitUsage = 0;
            var runGroupOnce = false;

            for (const it in instanceMap.instanceType) {
                if (instanceMap.groupInstanceTypes[it] && runGroupOnce === false) {
                    ec2Vcpus = instanceMap.groupVcpus[it];
                    ec2VcpusLimit = instanceMap.limit[it];
                    ec2VcpusLimitUsage = instanceMap.limitUsage[it];
                    runGroupOnce = true;
                } else if (instanceMap.groupInstanceTypes[it] && runGroupOnce === true) {
                    continue;
                } else {
                    ec2Vcpus = instanceMap.vcpus[it];
                    ec2VcpusLimit = instanceMap.limit[it];
                    ec2VcpusLimitUsage = instanceMap.limitUsage[it];
                }

                var returnMsg = 'Account contains ' + ec2Vcpus + ' of ' + ec2VcpusLimit + ' vCPUs (' + ec2VcpusLimitUsage + '%) for on-demand ' + (instanceMap.groupInstanceTypes[it] ? instanceMap.groupInstanceTypes[it].toString().toUpperCase().replace(/,/g, ', ') : instanceMap.instanceType[it].toString().toUpperCase()) + ' instances';

                if (ec2VcpusLimitUsage >= config.instance_limit_percentage_fail) {
                    helpers.addResult(results, 2, returnMsg, region, null, custom);
                } else if (ec2VcpusLimitUsage >= config.instance_limit_percentage_warn) {
                    helpers.addResult(results, 1, returnMsg, region, null, custom);
                } else {
                    helpers.addResult(results, 0, returnMsg, region, null, custom);
                }
            }

            rcb();
        }

        async.each(regions.ec2, function(region, rcb) {

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            if (describeInstances.data.length) {
                if (regions.servicequotas.includes(region)) {
                    // Regions that support vCPUs, new calculation method below
                    checkVcpusLimits(describeInstances, region, rcb);
                } else {
                    // Not all regions support vCPUs, legacy calculation method below
                    checkLegacyRegion(describeInstances, region, rcb);
                }
            } else {
                helpers.addResult(results, 0, 'No instances found', region);
                rcb();
            }
        }, function() {
            callback(null, results, source);
        });
    }
};