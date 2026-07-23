const expect = require('chai').expect;
var lambdaPublicAccess = require('./lambdaPublicAccess');

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler"
    }
];

const getPolicy = [
    {
        "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"sns\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"lambda:*\",\"Resource\":\"arn:aws:lambda:us-east-1:000011112222:function:test-lambda\"}]}",
        "RevisionId": "3ed6bad6-8315-4aee-804a-ba9d332a8952"
    },
    {
        "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"sns\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"lambda:*\",\"Resource\":\"arn:aws:lambda:us-east-1:000011112222:function:test-lambda\"},{\"Sid\":\"global\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"lambda:*\",\"Resource\":\"arn:aws:lambda:us-east-1:000011112222:function:test-lambda\"}]}",
        "RevisionId": "3ed6bad6-8315-4aee-804a-ba9d332a8952"
    }
];



const createCache = (listFunctions, getPolicy, listFunctionsErr, getPolicyErr) => {
    var functionName = (listFunctions && listFunctions.length) ? listFunctions[0].FunctionName : null;
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: listFunctionsErr,
                    data: listFunctions
                }
            },
            getPolicy: {
                'us-east-1': {
                    [functionName]: {
                        err: getPolicyErr,
                        data: getPolicy
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

describe('lambdaPublicAccess', function () {
    describe('run', function () {

        it('should PASS if function policy does not allow global access', function (done) {
            const cache = createCache([listFunctions[0]], getPolicy[0], null, null);
            lambdaPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if function policy allows global access', function (done) {
            const cache = createCache([listFunctions[0]], getPolicy[1], null, null);
            lambdaPublicAccess.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if function does not have an access policy', function (done) {
            const cache = createCache([listFunctions[0]], getPolicy[1], null, { code: "ResourceNotFoundException" });
            lambdaPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no Lambda functons found', function (done) {
            const cache = createCache([]);
            lambdaPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createCache(null, null, { message: "Unable to list functions" }, null);
            lambdaPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get function role policy', function (done) {
            const cache = createCache([listFunctions[0]], getPolicy[1], null, { message: "Unable to get function role policy" });
            lambdaPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Lambda functions response not found', function (done) {
            const cache = createNullCache();
            lambdaPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});