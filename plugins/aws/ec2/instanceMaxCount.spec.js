var expect = require('chai').expect;
const instanceMaxCount = require('./instanceMaxCount');

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
                "State": {
                    "Code": 80,
                    "Name": "running"
                },
            },
        ],
    },
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
            }
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


describe('instanceMaxCount', function () {
    describe('run', function () {
        it('should PASS if instances are within the regional and global expected count', function (done) {
            const cache = createCache([describeInstances[0]]);
            var settings = {
                instance_count_global_threshold: 2,
                instance_count_region_threshold_us_east_1: 1
            };

            instanceMaxCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instances are not in the regional expected count', function (done) {
            const cache = createCache([describeInstances[0],describeInstances[0]]);
            var settings = {
                instance_count_global_threshold: 2,
                instance_count_region_threshold_us_east_1: 1
            };

            instanceMaxCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instances are not in the global expected count', function (done) {
            const cache = createCache([describeInstances[0],describeInstances[0]]);
            var settings = {
                instance_count_global_threshold: 1,
                instance_count_region_threshold_us_east_1: 2
            };

            instanceMaxCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if instances are not in the regional and global expected count', function (done) {
            const cache = createCache([describeInstances[0],describeInstances[0]]);
            var settings = {
                instance_count_global_threshold: 1,
                instance_count_region_threshold_us_east_1: 1
            };

            instanceMaxCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache([]);
            instanceMaxCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to describe instances', function (done) {
            const cache = createErrorCache();
            instanceMaxCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should PASS if describe instances response not found', function (done) {
            const cache = createNullCache();
            instanceMaxCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});