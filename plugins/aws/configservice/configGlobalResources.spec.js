var expect = require('chai').expect;;
var configGlobalResources = require('./configGlobalResources');

const describeConfigurationRecorders = [
    {
        "name": "default",
        "roleARN": "arn:aws:iam::101363889637:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "recordingGroup": {
            "allSupported": true,
            "includeGlobalResourceTypes": true,
            "resourceTypes": []
        }
    },
    {
        "name": "default",
        "roleARN": "arn:aws:iam::101363889637:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "recordingGroup": {
            "allSupported": true,
            "includeGlobalResourceTypes": false,
            "resourceTypes": []
        }
    }
];

const createCache = (recorders) => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                "us-east-1": {
                    data: recorders                },
            }
        }
    }
}

const createNullCache = () => {
    return {
        configservice: {
            describeConfigurationRecorders: {
                "us-east-1": {
                    data: null
                }
            }
        }
    }
}

describe('configGlobalResources', () => {
    describe('run', () => {
        it('should PASS if The configuration changes made to your AWS Global resources are currently recorded', () => {
            const cache = createCache([describeConfigurationRecorders[0]]);
            configGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            })
        });
        it('should FAIL if The configuration changes made to your AWS Global resources are not currently recorded', () => {
            const cache = createCache([describeConfigurationRecorders[1]]);
            configGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            })
        });
        it('should UNKNOWN if Unable to query for Config Service', () => {
            const cache = createNullCache();
            configGlobalResources.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
            })
        });
        it('should not return anything if list config services response is not found', () => {
            configGlobalResources.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});