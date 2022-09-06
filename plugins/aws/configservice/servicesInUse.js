var async = require('async');
var helpers = require('../../../helpers/aws');
// const { athena, finspace, healthlake } = require('../../../helpers/aws/regions');

module.exports = {
    title: 'AWS Services In Use',
    category: 'ConfigService',
    domain: 'Management and Governance',
    severity: 'MEDIUM',
    description: 'Ensures that only permitted services are being used in you AWS cloud account.',
    more_info: 'Use only permitted AWS services in your cloud account in order to meet security and compliance requirements within your organization.',
    recommended_action: 'Delete resources from unpermitted services within your AWS cloud account.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html',
    apis: ['ConfigService:describeConfigurationRecorderStatus', 'ConfigService:getDiscoveredResourceCounts'],
    settings: {
        allowed_services_list: {
            name: 'Allowed Service List',
            description: 'Comma separated list of allowed services such as ec2,iam,s3',
            regex: '^.*$',
            default:''
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            allowed_services_list:(settings.allowed_services_list || this.settings.allowed_services_list.default)
        };

        config.allowed_services_list = config.allowed_services_list.replace(/\s/g, '');

        if (!config.allowed_services_list.length) return callback(null, results, source);
        
        config.allowed_services_list = config.allowed_services_list.toLowerCase().split(',');

        const allServices = {
            'accessanalyzer': 'accessanalyzer',
            'appflow': 'af',
            'appmesh': 'am',
            'apprunner': 'ar',
            'athena': 'athena',
            'auditmanager': 'auditmanager',
            'apigateway': 'apigateway' ,
            'cloudfront': 'cfn',
            'dynamodb': 'dynamodb',
            'documentdb': 'documentdb',
            'ec2':'ec2',
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
            'healthake': 'healthlake',
            'imagebuilder': 'ib',
            'kendra': 'kendra',
            'lex': 'lex',
            'location': 'location',
            'managedblockchain': 'mnb',
            'memorydb': 'memorydb',
            'mq': 'mq',
            'msk': 'msk',
            'mwaa': 'mwaa',
            'neptune': 'neptune', 
            'guardduty': 'guardduty',
            'elasticsearch': 'es',
            'opensearch': 'opensearch',
            'organizations': 'organizations',
            'proton': 'proton',
            'route53': 'route53',
            'qldb': 'qldb',
            'kinesis': 'kinesis',
            'redshift': 'redshift',
            'rds': 'rds',
            'sagemaker': 'sagemaker',
            's3': 's3',
            'autoscaling': 'autoscaling',
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
            'devopsguru': 'devopsguru',
            'elasticbeanstalk': 'ebs',
            'iam': 'iam',
            'kms':  'kms',
            'lambda': 'lambda',
            'networkfirewall': 'networkfirewall',
            'secretsmanager': 'secretsmanager',
            'servicecatalog': 'servicecatalog',
            'shield': 'shield',
            'sns': 'sns',
            'sqs': 'sqs',
            'stepfunctions': 'stepfunctions',
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

            usedServicesShorthand = usedServicesShorthand.filter(service => !config.allowed_services_list.includes(service));
            if (usedServicesShorthand.length){
                helpers.addResult(results, 2,
                    'These unpermitted services are being used: ' + usedServicesShorthand.join(','), region);
            } else {
                helpers.addResult(results, 0,
                    'Only allowed services are being used', region);
            }

            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};

