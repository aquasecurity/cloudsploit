// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'us-east-1',        // Northern Virginia
    'us-east-2',        // Ohio
    'us-west-1',        // Northern California
    'us-west-2',        // Oregon
    'af-south-1',        // Africa (Cape Town)
    'ap-east-1',        // Asia Pacific (Hong Kong)
    'ap-south-1',       // Asia Pacific (Mumbai)
    'ap-northeast-3',   // Asia Pacific (Osaka)
    'ca-central-1',     // Canada (Montreal)
    'eu-central-1',     // EU (Frankfurt)
    'eu-west-1',        // EU (Ireland)
    'eu-west-2',        // London
    'eu-west-3',        // Paris
    'eu-north-1',       // Stockholm
    'eu-south-1',       // EU (Milan)
    'ap-northeast-1',   // Asia Pacific (Tokyo)
    'ap-northeast-2',   // Asia Pacific (Seoul)
    'ap-southeast-1',   // Asia Pacific (Singapore)
    'ap-southeast-2',   // Asia Pacific (Sydney)
    'sa-east-1',        // South America (São Paulo)
    'me-south-1',       // Middle East (Bahrain)
];
var meCentral1 = [
    'me-central-1'      // Middle East (UAE)
];

var newRegions = [
    'ap-southeast-3',   // Asia Pacific (Jakarta)
];

var newRegionsUpdate =[
    'ap-south-2',       // Asia Pacific (Hyderabad)
    'ap-southeast-4',   // Asia Pacific (Melbourne)
    'eu-south-2',      // Europe (Spain)
    'eu-central-2'     // Europe (Zurich)
];

module.exports = {
    default: ['us-east-1'],
    all: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    optin: ['ap-east-1', 'me-south-1', 'ap-southeast-3'],   // Regions that AWS disables by default
    accessanalyzer: [...regions, ...newRegions, ...newRegionsUpdate],
    acm: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    apigateway: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    athena: regions,
    cloudfront: ['us-east-1'], // CloudFront uses the default global region
    autoscaling: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    iam: ['us-east-1'],
    route53: ['us-east-1'],
    route53domains: ['us-east-1'],
    s3: ['us-east-1'],
    s3control: ['us-east-1'],
    cognitoidentityserviceprovider: [ 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1','eu-central-1',     
        'eu-west-1','eu-west-2', 'eu-west-3','eu-north-1', 'eu-south-1','ap-northeast-1','ap-northeast-2',
        'ap-southeast-1', 'ap-south-1', 'sa-east-1', 'me-south-1', 'ap-southeast-4',  'eu-south-2','eu-central-2' 
    ],
    cloudformation: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    cloudtrail: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    cloudwatchlogs: [...regions, ...newRegions, ...meCentral1,...newRegionsUpdate],
    comprehend: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1',
        'ap-southeast-2', 'ap-northeast-2', 'ap-south-1', 'ca-central-1', 'ap-southeast-4',
        'eu-south-2','eu-central-2'],
    configservice: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    dax: ['us-east-1'], // available Globally
    devopsguru: ['us-east-1', 'us-east-2', 'eu-west-1', 'eu-west-2', 'eu-west-3','ap-northeast-1', 'eu-central-1',
        'ap-southeast-1', 'ap-southeast-2', 'eu-north-1', 'ap-south-1', 'ap-northeast-2', 'ca-central-1','eu-central-1',
        'sa-east-1', 'sa-west-1', 'ap-southeast-4',  'eu-south-2','eu-central-2'],
    dynamodb: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    docdb: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1'
    ],
    dlm: [...regions, ...newRegions, ...meCentral1, 'ap-southeast-4'],
    dms: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    ec2: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    ecr: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    eks: [...regions, ...newRegions, 'eu-south-2','eu-central-2', 'ep-south-2', 'ap-southeast-3'],
    elasticbeanstalk: [...regions, ...newRegions, ...meCentral1],
    elastictranscoder: ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-south-1'],
    elb: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    elbv2: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    eventbridge: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    emr: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    es: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    glue: [...regions, ...newRegions, ...meCentral1],
    kinesis: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    kinesisvideo:  ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-northeast-1','ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'ap-east-1','sa-east-1'],
    firehose: [...regions, ...newRegions,...meCentral1, ...newRegionsUpdate],
    kms: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    vpc: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    flowlogs: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    rds: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    redshift: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    cloudwatch: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    ecs: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    resourcegroupstaggingapi: [...regions, ...newRegions, ...newRegionsUpdate, ...meCentral1],
    sagemaker: [...regions, ...newRegions, ...meCentral1],
    secretsmanager: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    ses: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-3', 'ap-south-1',
        'sa-east-1', 'me-south-1', 'af-south-1', 'ap-southeast-3'],
    sns: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    sqs: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    ssm: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    shield: ['us-east-1'],
    sqs_encrypted: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    sts: ['us-east-1'],
    transfer: [...regions, ...newRegions, ...meCentral1],
    lambda: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    mwaa: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-south-1', 'eu-north-1', 'eu-central-1',
        'ap-southeast-2', 'ap-southeast-1', 'ap-northeast-2', 'ap-northeast-1', 'ca-central-1', 'sa-east-1'],
    directconnect: ['us-east-1'], // this is global service
    directoryservice: [...regions, ...newRegions, 'ap-south-2', 'eu-south-2', 'eu-central-2', ...meCentral1],
    efs: [...regions, ...newRegions, ...meCentral1, 'eu-south-2', 'eu-central-2'],
    support: ['us-east-1'],
    wafregional: regions,
    wafv2: [...regions, ...meCentral1, ...newRegions],
    waf: ['us-east-1'],
    organizations: ['us-east-1'],
    guardduty: [...regions, ...newRegions, ...meCentral1],
    workspaces: ['us-east-1', 'us-west-2', 'ca-central-1', 'sa-east-1', 'ap-south-1',
        'eu-west-1', 'eu-central-1', 'eu-west-2', 'ap-southeast-1',
        'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2', 'af-south-1'],
    servicequotas: [...regions, ...newRegions, ...meCentral1],
    xray: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    codestar: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-north-1'],
    codebuild: [...regions, ...newRegions, ...meCentral1],
    mq: [...regions, ...newRegions, ...meCentral1],
    glacier: regions,
    backup: [...regions, ...newRegions, ...meCentral1],
    elasticache: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate],
    timestreamwrite:  ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 'ap-southeast-2',
        'ap-northeast-1'],
    neptune: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'me-south-1', 'af-south-1'
    ],
    memorydb: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 
        'eu-west-1', 'eu-west-2', 'eu-north-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1'],
    kafka: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'me-south-1', 'af-south-1'],
    kendra:  ['us-east-1', 'us-east-2', 'us-west-2', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-west-1'],
    proton: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-1', 'eu-west-1', 'eu-west-2', 'eu-central-1',
        'ca-central-1', 'ap-southeast-2', 'ap-southeast-1', 'ap-northeast-2'],
    customerprofiles: ['us-east-1', 'us-west-2', 'eu-west-2', 'ca-central-1', 'eu-central-1',
        'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2'],
    qldb: ['us-east-1', 'us-east-2', 'us-west-2', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2'],
    finspace: ['us-east-1', 'us-east-2', 'us-west-2', 'ca-central-1','eu-west-1'],
    codepipeline: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1',
        'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'ap-east-1',
        'sa-east-1'],
    codeartifact: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'],
    auditmanager: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'
    ],
    appflow: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2',
        'eu-west-3', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'af-south-1'
    ],
    translate: [
        'us-east-1', 'us-east-2', 'us-west-1','us-west-2', 'eu-west-1', 'eu-west-2', 'ap-northeast-2',
        'ap-east-1','af-south-1', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-west-3', 'eu-central-1',
        'eu-north-1'
    ],
    databrew: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 
        'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'ap-east-1', 'af-south-1'
    ],
    managedblockchain: ['us-east-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-northeast-1', 'eu-west-1', 'eu-west-2'],
    connect: ['us-east-1', 'us-west-2', 'eu-west-2', 'ca-central-1', 'eu-central-1',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'af-south-1'],
    apprunner:  ['us-east-1', 'us-west-2', 'us-west-2', 'eu-west-1','ap-northeast-1'],
    healthlake: ['us-east-1', 'us-east-2', 'us-west-2'],
    lookoutequipment: ['us-east-1', 'eu-west-1', 'ap-northeast-2'],
    iotsitewise: ['us-east-1', 'us-west-2', 'ap-south-1', 'ap-southeast-1', 'ap-northeast-2', 'ap-southeast-2',
        'ap-northeast-1', 'eu-central-1', 'eu-west-1', 'ca-central-1', 'us-east-2'],
    location: [
        'us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 'eu-north-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', 'sa-east-1', 'eu-west-2', 'ca-central-1', 'ap-south-1'
    ],
    lookoutvision: ['us-east-1', 'us-east-2', 'ap-northeast-1',  'ap-northeast-2', 'eu-central-1', 'eu-west-1', 'us-west-2'],
    lookoutmetrics: ['us-east-1', 'us-east-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'eu-central-1',
        'eu-west-1', 'eu-north-1', 'us-west-2'],
    forecastservice: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-central-1', 'eu-west-1', 
        'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-south-1'],
    lexmodelsv2: [ 'us-east-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1',
        'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'af-south-1'],
    fsx: [...regions, ...newRegions, ...meCentral1],
    wisdom: ['us-east-1', 'us-west-2', 'eu-west-2', 'eu-central-1', 'ap-northeast-1', 'ap-southeast-2'],
    voiceid: ['us-east-1', 'us-west-2', 'eu-west-2', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2'],
    appmesh:  [...regions, ...newRegions, ...meCentral1],
    frauddetector: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-southeast-2'],
    imagebuilder: [...regions, ...newRegions, ...meCentral1],
    computeoptimizer: ['us-east-1'],
    appconfig: [...regions, ...newRegions, ...meCentral1, ...newRegionsUpdate]
};
