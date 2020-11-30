var expect = require('chai').expect;
const instanceKeyBasedLogin = require('./instanceKeyBasedLogin');

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
                    "Arn": "arn:aws:iam::112233445566:instance-profile/aws-elasticbeanstalk-ec2-role",
                    "Id": "AIPAYE32SRU5VWPEXDHQE"
                },
            },
        ],
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::112233445566:instance-profile/aws-elasticbeanstalk-ec2-role",
                    "Id": "AIPAYE32SRU5VWPEXDHQE"
                },
            },
        ],
    }
];

const createCache = (instances) => {
    return {
        ec2:{
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
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': null,
            },
        },
    };
};


describe('instanceKeyBasedLogin', function () {
    describe('run', function () {
        it('should PASS if instance has associated keys for password-less SSH login', function (done) {
            const cache = createCache([describeInstances[0]]);
            var settings = {
                instance_keypair_threshold: 2,
            };
            instanceKeyBasedLogin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instance does not have associated keys for password-less SSH login', function (done) {
            const cache = createCache([describeInstances[1]]);
            var settings = {
                instance_keypair_threshold: 2,
            };
            instanceKeyBasedLogin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if EC2 instances do not have associated keys for password-less SSH login', function (done) {
            const cache = createCache([describeInstances[1],describeInstances[1],describeInstances[1]]);
            var settings = {
                instance_keypair_threshold: 2,
            };
            instanceKeyBasedLogin.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache([]);
            instanceKeyBasedLogin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe instances', function (done) {
            const cache = createErrorCache();
            instanceKeyBasedLogin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe instances response not found', function (done) {
            const cache = createNullCache();
            instanceKeyBasedLogin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
