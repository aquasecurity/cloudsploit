const expect = require('chai').expect;
var lambdaVpcConfig = require('./lambdaVpcConfig');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler",
        "VpcConfig": {
            "SubnetIds": [
                "subnet-6a8b635b",
                "subnet-c21b84cc"
            ],
            "SecurityGroupIds": [
                "sg-001639e564442dfec"
            ],
            "VpcId": "vpc-99de2fe4"
        },
    },
    {
        "FunctionName": "testing-123",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-123",
        "Runtime": "nodejs4.3",
        "Role": "arn:aws:iam::000011112222:role/service-role/testing-123-role-7t7oo29b",
        "Handler": "index.handler",
    }
];


const createCache = (listFunctions) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: listFunctions
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: {
                        message: 'error listing Lambda functions'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': null
            }
        }
    };
};

describe('lambdaVpcConfig', function () {
    describe('run', function () {

        it('should PASS if the function is whitelisted', function (done) {
            const cache = createCache([listFunctions[1]]);
            lambdaVpcConfig.run(cache, { lambda_whitelist: 'testing-123' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if function is being launched into a VPC', function (done) {
            const cache = createCache([listFunctions[0]]);
            lambdaVpcConfig.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if function is not being launched into a VPC', function (done) {
            const cache = createCache([listFunctions[1]]);
            lambdaVpcConfig.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Lambda functons found', function (done) {
            const cache = createCache([]);
            lambdaVpcConfig.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createErrorCache();
            lambdaVpcConfig.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Lambda functions response not found', function (done) {
            const cache = createNullCache();
            lambdaVpcConfig.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});