var expect = require('chai').expect;
const instanceLimit = require('./instanceLimit');

const describeAccountAttributes = [
    [
        {
            "AttributeName": "max-instances",
            "AttributeValues": [
                {
                    "AttributeValue": "5"
                }
            ]
        },
    ]
];

const describeInstances = [
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "KeyName": "auto-scaling-test-instance",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/aws-elasticbeanstalk-ec2-role",
                    "Id": "AIPAYE32SRU5VWPEXDHQE"
                },
            },
        ],
    },
];

const createCache = (attributes, instances) => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': {
                    data: attributes
                },
            },
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing account attributes'
                    },
                },
            },
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': null,
            },
            describeInstances: {
                'us-east-1': null,
            },
        },
    };
};


describe('instanceLimit', function () {
    describe('run', function () {
        it('should PASS if account contains instances less than the defined warn percentage', function (done) {
            const cache = createCache(describeAccountAttributes[0],[describeInstances[0]]);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if account contains instances within the defined warn percentage', function (done) {
            const cache = createCache(describeAccountAttributes[0],[describeInstances[0],describeInstances[0],describeInstances[0],describeInstances[0]]);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if elastic ip usage is more than the defined fail percentage', function (done) {
            const cache = createCache(describeAccountAttributes[0],[describeInstances[0],describeInstances[0],describeInstances[0],describeInstances[0],describeInstances[0]]);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache(describeAccountAttributes[0], []);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to describe account attributes', function (done) {
            const cache = createErrorCache();
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should FAIL if unable to describe instances', function (done) {
            const cache = createCache([]);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe account attributes response not found', function (done) {
            const cache = createNullCache();
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});