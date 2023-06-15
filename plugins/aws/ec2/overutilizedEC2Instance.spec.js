const expect = require('chai').expect;
const overutilizedEC2Instance = require('./overutilizedEC2Instance');

const describeInstances = [
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0a985f18de454c879",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-11-18T22:48:08.000Z",
                "SubnetId": "subnet-aac6b3e7",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111222333444:instance-profile/test-role-1",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "Tags": [
                    {
                        "Key": "app-tier",
                        "Value": "app-tier"
                    }
                ],
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-087ce52925d75c272"
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-036d7bf13e0bfe836",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111222333444:instance-profile/test-ec2-role-2",
                    "Id": "AIPAYE32SRU5VWPEXDHQE"
                },
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-1323e23rede231231"
    }
];


const ec2MetricStatistics = [
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 4.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 3.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 6.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 2.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 1.333,
                "Unit": "Percent"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 94.99,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 90.70,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 99.20,
                "Unit": "Percent"
            },
        ]
    }
]

const createCache = (instance, metrics) => {
    if (instance && instance.length) var id = instance[0].Instances[0].InstanceId;
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: instance,
                },
            },
        },
        cloudwatch: {
            getEc2MetricStatistics: {
                'us-east-1': {
                    [id]: {
                        data: metrics
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error desribing cache clusters'
                    },
                },
            },
        },
        cloudwatch: {
            getEc2MetricStatistics: {
                'us-east-1': {
                    err: {
                        message: 'error getting metric stats'
                    },
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': null,
            },
        },
        cloudwatch: {
            getEc2MetricStatistics: {
                'us-east-1': null
            },
        },
    };
};

describe('overutilizesEC2Instance', function () {
    describe('run', function () {
        it('should PASS if the EC2 Instance cpu utilization is less than 90 percent', function (done) {
            const cache = createCache([describeInstances[0]], ec2MetricStatistics[0]);
            overutilizedEC2Instance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if the EC2 Instance cpu utilization is more than 90 percent', function (done) {
            const cache = createCache([describeInstances[1]], ec2MetricStatistics[1]);
            overutilizedEC2Instance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no EC2 Instance found', function (done) {
            const cache = createCache([]);
            overutilizedEC2Instance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No EC2 instances found');
                done();
            });
        });

        it('should UNKNOWN if unable to describe EC2 Instance', function (done) {
            const cache = createErrorCache();
            overutilizedEC2Instance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for EC2 instances: ');
                done();
            });
        });

        it('should not return any results if describe EC2 Instance response not found', function (done) {
            const cache = createNullCache();
            overutilizedEC2Instance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        }); 
    });
});
