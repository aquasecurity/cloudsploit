var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Services In Use',
    category: 'ConfigService',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that only permitted services are being used in you AWS cloud account.',
    more_info: 'Use only permitted AWS services in your cloud account in order to meet security and compliance requirements within your organization.',
    recommended_action: 'Delete resources from unpermitted services within your AWS cloud account.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html',
    apis: ['ConfigService:describeConfigurationRecorderStatus', 'ConfigService:getDiscoveredResourceCounts'],
    settings: {
        permitted_services_list: {
            name: 'Permitted Service List',
            description: 'Comma separated list of permitted services such as ec2,iam,s3. Choose only one setting at a time.',
            regex: '^.*$',
            default:''
        },
        unpermitted_services_list: {
            name: 'Unpermitted Service List',
            description: 'Comma separated list of unpermitted services such as ec2,iam,s3. Choose only one setting at a time.',
            regex: '^.*$',
            default:''
        },
    },
    realtime_triggers: ['configservice:PutConfigurationRecorder','configservice:StartConfigurationRecorder','configservice:StopConfigurationRecorder'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            permitted_services_list:(settings.permitted_services_list || this.settings.permitted_services_list.default),
            unpermitted_services_list:(settings.unpermitted_services_list || this.settings.unpermitted_services_list.default)
        };

        config.permitted_services_list = config.permitted_services_list.replace(/\s/g, '');
        config.unpermitted_services_list = config.unpermitted_services_list.replace(/\s/g, '');

        if (!config.permitted_services_list.length && !config.unpermitted_services_list.length) return callback(null, results, source);

        var checkPermitted = (config.permitted_services_list.length > 0);
        
        config.permitted_services_list = config.permitted_services_list.toLowerCase().split(',');

        const allServices = {
            'accessanalyzer': 'aa',
            'appflow': 'af',
            'appmesh': 'am',
            'apprunner': 'ar',
            'athena': 'athena',
            'auditmanager': 'auditmngr',
            'apigateway': 'agway' ,
            'cloudfront': 'cfn',
            'dynamodb': 'dynamo',
            'documentdb': 'docdb',
            'ec2': 'ec2',
            'ecr': 'ecr',
            'ecs': 'ecs',
            'efs': 'efs',
            'eks': 'eks',
            'emr': 'emr',
            'elasticache': 'ec',
            'elastictranscoder': 'et',
            'eventbridge': 'eb',
            'finspace': 'finspace',
            'firehose': 'firehose',
            'forecast': 'forecast',
            'frauddetector': 'fd',
            'fsx': 'fsx',
            'glue': 'glue',
            'healthake': 'hlake',
            'imagebuilder': 'ib',
            'kendra': 'kendra',
            'lex': 'lex',
            'location': 'location',
            'managedblockchain': 'mbc',
            'memorydb': 'memdb',
            'mq': 'mq',
            'msk': 'msk',
            'mwaa': 'mwaa',
            'neptune': 'neptune', 
            'guardduty': 'gd',
            'elasticsearch': 'es',
            'opensearch': 'opensearch',
            'organizations': 'orgs',
            'proton': 'proton',
            'route53': 'r53',
            'qldb': 'qldb',
            'kinesis': 'kinesis',
            'redshift': 'redshift',
            'rds': 'rds',
            'sagemaker': 'sagemaker',
            's3': 's3',
            'autoscaling': 'as',
            'backup': 'backup',
            'acm': 'acm',
            'cloudformation': 'cfn',
            'cloudwatch': 'cw',
            'cloudwatchlogs': 'cwl',
            'codeartifact': 'ca',
            'codestar': 'cs',
            'comprehend': 'comprehend',
            'computeoptimizer': 'co',
            'dms': 'dms',
            'cloudtrail': 'ct',
            'codebuild': 'cb',
            'codedeploy': 'cd',
            'codepipeline': 'cp',
            'config': 'config',
            'connect': 'connect',
            'devopsguru': 'dog',
            'elasticbeanstalk': 'ebs',
            'iam': 'iam',
            'kms':  'kms',
            'lambda': 'lambda',
            'networkfirewall': 'nf',
            'secretsmanager': 'sm',
            'servicecatalog': 'sc',
            'shield': 'shield',
            'sns': 'sns',
            'sqs': 'sqs',
            'stepfunctions': 'sf',
            'ssm': 'ssm',
            'waf': 'waf',
            'timestreamwrite':'tsw',
            'transfer': 'transfer',
            'translate': 'translate',
            'workspaces': 'workspaces', 
            'wafv2': 'wafv2',
            'xray': 'xray',
            'elasticloadbalancing': 'elb',
            'elasticloadbalancingv2': 'elbv2'
        };

        async.each(regions.configservice, function(region, rcb){        
            var configRecorderStatus = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorderStatus', region]);

            if (!configRecorderStatus) {
                return rcb();
            }

            if (configRecorderStatus.err || !configRecorderStatus.data) {
                helpers.addResult(results, 3,
                    'Unable to query config service: ' + helpers.addError(configRecorderStatus), region);
                return rcb();
            }

            if (!configRecorderStatus.data.length) {
                helpers.addResult(results, 2,
                    'Config service is not enabled', region);
                return rcb();
            }

            if (!configRecorderStatus.data[0].recording) {
                helpers.addResult(results, 2,
                    'Config service is not recording', region);
                return rcb();
            }

            if (!configRecorderStatus.data[0].lastStatus ||
                (configRecorderStatus.data[0].lastStatus.toUpperCase() !== 'SUCCESS' &&
                configRecorderStatus.data[0].lastStatus.toUpperCase() !== 'PENDING')) {
                helpers.addResult(results, 2,
                    'Config Service is configured, and recording, but not delivering properly', region);
                return rcb();
            }

            var discoveredResources = helpers.addSource(cache, source,
                ['configservice', 'getDiscoveredResourceCounts', region]);

            if (discoveredResources.err || !discoveredResources.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Discovered Resources: ' + helpers.addError(discoveredResources));
                return rcb();
            }

            let usedServices = [];
            for (let resource of discoveredResources.data){
                if (resource.resourceType){
                    let newResource = resource.resourceType.split('::');
                    if (newResource.length > 1 && !usedServices.includes(newResource[1].toLowerCase())) usedServices.push(newResource[1].toLowerCase());
                }
            }

            let usedServicesShorthand = [];
            for (let value of usedServices){
                if (allServices[value]) usedServicesShorthand.push(allServices[value]);
            }

            if (checkPermitted) {
                usedServicesShorthand = usedServicesShorthand.filter(service => !config.permitted_services_list.includes(service));
                if (usedServicesShorthand.length){
                    helpers.addResult(results, 2,
                        'These unpermitted services are being used: ' + usedServicesShorthand.join(','), region);
                } else {
                    helpers.addResult(results, 0,
                        'Only allowed services are being used', region);
                }
            } else {
                usedServicesShorthand = usedServicesShorthand.filter(service => config.unpermitted_services_list.includes(service));
                if (usedServicesShorthand.length){
                    helpers.addResult(results, 2,
                        'These unpermitted services are being used: ' + usedServicesShorthand.join(','), region);
                } else {
                    helpers.addResult(results, 0,
                        'Only allowed services are being used', region);
                }
            }

            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};

