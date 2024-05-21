const expect = require('chai').expect;
const wafv2WebAclLoggingEnabled = require('./wafv2WebAclLoggingEnabled');

const listWebACLsResponse = [
    {
        "Id": "abcd1234",
        "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/abcd1234",
        "Name": "TestWebACL",
        "Description": "Test Web ACL",
        "VisibilityConfig": {
            "SampledRequestsEnabled": true,
            "CloudWatchMetricsEnabled": false,
            "MetricName": "TestWebACL"
        }
    },
];

const loggingEnabledResponse = {
    "LoggingConfiguration": {
        "LogDestinationConfigs": [
            "arn:aws:logs:us-east-1:123456789012:log-group:/aws/wafv2/abcd1234/web-acl"
        ],
        "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/abcd1234"
    }
};


const createCache = (listWebACLsResponse, loggingConfigurations) => {
    return {
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    data: listWebACLsResponse,
                    err: null
                }
            },
            getLoggingConfiguration: {
                'us-east-1': {
                    'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/abcd1234': {
                        data: loggingConfigurations,
                        err: null
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    err: {
                        message: 'error listing Web ACLs'
                    }
                }
            },
            getLoggingConfiguration: {
                'us-east-1': {
                    err: {
                        message: 'error getting logging configuration'
                    }
                }
            }
        }
    };
};

const createFalseCache = ()=>{
    return {
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    data: listWebACLsResponse,
                    err: null
                }
            },
            getLoggingConfiguration: {
                'us-east-1': {
                    'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/abcd1234': {
                        err: {
                            code: 'WAFNonexistentItemException'
                        }
                    }
                }
            }
        }
    };
}

describe('wafv2WebAclLoggingEnabled', function () {
    describe('run', function () {

        it('should PASS if logging is enabled for all Web ACLs', function (done) {
            const cache = createCache(listWebACLsResponse, loggingEnabledResponse);
            wafv2WebAclLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(listWebACLsResponse.length);
                results.forEach(result => {
                    expect(result.status).to.equal(0);
                    expect(result.region).to.equal('us-east-1');
                    expect(result.message).to.include('Logging for web ACL is enabled');
                });
                done();
            });
        });

        it('should FAIL if logging is disabled for any Web ACL', function (done) {
            const cache = createFalseCache();
            wafv2WebAclLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(listWebACLsResponse.length);
                results.forEach(result => {
                    expect(result.status).to.equal(2);
                    expect(result.region).to.equal('us-east-1');
                    expect(result.message).to.include('Logging for web ACL is disabled');

                });
                done();
            });
        });

        it('should handle error if unable to list Web ACLs', function (done) {
            const cache = createErrorCache();
            wafv2WebAclLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list WAFV2 web ACLs:');
                done();
            });
        });

        it('should handle error if unable to get logging configuration for Web ACLs', function (done) {
            const cache = createCache(listWebACLsResponse, {
            });
            wafv2WebAclLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(listWebACLsResponse.length);
                results.forEach(result => {
                    expect(result.status).to.equal(3);
                    expect(result.region).to.equal('us-east-1');
                    expect(result.message).to.include('Unable to get WAFV2 web ACL logging configuration:');
                });
                done();
            });
        });
    });
});