// Source: https://www.alibabacloud.com/help/en/doc-detail/40654.htm

var regions = [
    'ap-southeast-1',         // Singapore
    'ap-southeast-2',         // Australia (Sydney)
    'ap-southeast-3',         // Malaysia (Kuala Lumpur)
    'ap-southeast-5',         // Indonesia (Jakarta)
    'ap-northeast-1',         // Japan (Tokyo)
    'ap-southeast-6',         // Philippines (Manila)
    'ap-south-1',             // India (Mumbai)
    'eu-central-1',           // Germany (Frankfurt)
    'eu-west-1',              // UK (London)
    'us-west-1',              // US (Silicon Valley)
    'us-east-1',              // US (Virginia)
    'me-east-1',              // UAE (Dubai)
];

module.exports = {
    default: ['cn-hangzhou'],
    all: regions,
    ecs: regions,
    apigateway: [ 'ap-southeast-6', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
        'ap-southeast-5', 'ap-northeast-1', 'ap-south-1', 'eu-central-1', 'eu-west-1', 'us-west-1', 'us-east-1', 'me-east-1'
    ],
    polardb: regions,
    ram: ['cn-hangzhou'],
    vpc: regions,
    rds: regions,
    sts: ['cn-hangzhou'],
    oss: ['cn-hangzhou'],
    kms: regions,
    actiontrail: [ 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-5', 'ap-northeast-1', 'ap-south-1',
        'eu-central-1', 'eu-west-1', 'us-west-1', 'us-east-1', 'me-east-1'
    ],
    ack: ['cn-hangzhou'],
    tds: ['ap-southeast-3', 'ap-southeast-1']
};
