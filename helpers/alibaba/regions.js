// Source: https://www.alibabacloud.com/help/en/doc-detail/40654.htm

var regions = [
    'cn-hangzhou',            // China (Hangzhou)
    'cn-shanghai',            // China (Shanghai)
    'cn-qingdao',             // China (Qingdao)
    'cn-beijing',             // China (Beijing)
    'cn-zhangjiakou',         // China (Zhangjiakou)
    'cn-huhehaote',           // China (Hohhot)
    'cn-wulanchabu',          // China (Ulanqab)
    'cn-shenzhen',            // China (Shenzhen)
    'cn-heyuan',              // China (Heyuan)
    'cn-chengdu',             // China (Chengdu)
    'cn-hongkong',            // China (Hong Kong)
    'cn-guangzhou',           // China (Guangzhou)
    'cn-nanjing',             // China (Nanjing)
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
    ecs: [ 'cn-hangzhou', 'cn-shanghai', 'cn-qingdao', 'cn-beijing', 'cn-zhangjiakou', 'cn-huhehaote', 'cn-wulanchabu',
        'cn-shenzhen', 'cn-heyuan', 'cn-chengdu', 'cn-hongkong', 'cn-guangzhou', 'cn-nanjing', 'ap-southeast-1', 'ap-southeast-2',
        'ap-southeast-3', 'ap-southeast-5', 'ap-northeast-1', 'ap-south-1', 'eu-central-1', 'eu-west-1', 'us-west-1', 'us-east-1', 'me-east-1'
    ],
    apigateway: [ 'cn-hangzhou', 'cn-shanghai', 'cn-qingdao', 'cn-beijing', 'cn-zhangjiakou', 'cn-huhehaote', 'ap-southeast-6',
        'cn-shenzhen', 'cn-heyuan', 'cn-chengdu', 'cn-hongkong', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
        'ap-southeast-5', 'ap-northeast-1', 'ap-south-1', 'eu-central-1', 'eu-west-1', 'us-west-1', 'us-east-1', 'me-east-1'
    ],
    polardb: regions,
    ram: ['cn-hangzhou'],
    vpc: regions,
    rds: regions,
    sts: ['cn-hangzhou'],
    oss: ['cn-hangzhou'],
    kms: regions,
    actiontrail: [ 'cn-hangzhou', 'cn-shanghai', 'cn-qingdao', 'cn-beijing', 'cn-zhangjiakou', 'cn-huhehaote', 'cn-wulanchabu',
        'cn-shenzhen', 'cn-heyuan', 'cn-chengdu', 'cn-hongkong', 'cn-guangzhou', 'cn-nanjing', 'ap-southeast-1', 'ap-southeast-2',
        'ap-southeast-3', 'ap-southeast-5', 'ap-northeast-1', 'ap-south-1', 'eu-central-1', 'eu-west-1', 'us-west-1', 'us-east-1', 'me-east-1'
    ],
    ack: ['cn-hangzhou'],
    tds: ['cn-hangzhou', 'ap-southeast-3', 'ap-southeast-1']
};
