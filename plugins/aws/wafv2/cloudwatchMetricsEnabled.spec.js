const expect = require('chai').expect;
var cloudwatchMetricsEnabled = require('./cloudwatchMetricsEnabled');

const webACLs = [
    {
        Name: "WebACLexample",
        Id: "234",
        ARN: "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-poc/234"
    },
]
const getWebAcl = [
    {
        WebACL: {
            "ARN": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-poc/234",
            "VisibilityConfig": {
                "CloudWatchMetricsEnabled": true,
            },

        }
    },
    {
        WebACL:{
            "ARN": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-poc/234",
            "VisibilityConfig": {
                "CloudWatchMetricsEnabled": false,
            },

        }
    }
]

const createCache = (webACLs, getWebAcl) => {
    var arn = (webACLs && webACLs.length) ? webACLs[0].ARN : null;
    return {
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    data: webACLs
                }
            },
            getWebACL: {
                'us-east-1': {
                    [arn]: {
                        data: getWebAcl
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
                        message: 'Error listing transfer servers'
                    }
                }
            }
        }
    };
};


describe('cloudwatchMetricsEnabled', function () {
    describe('run', function () {
        it('should PASS if cloud watch metrics are enabled', function (done) {
            const cache = createCache([webACLs[0]], getWebAcl[0]);
            cloudwatchMetricsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cloud watch metrics are enabled for web ACL rule');
                done();
            });
        });

        it('should FAIL if cloud watch metrics are not enabled for webacl', function (done) {
            const cache = createCache([webACLs[0]], getWebAcl[1]);
            cloudwatchMetricsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cloud watch metrics are not enabled for web ACL rule');
                done();
            });
        });

        it('should unknown if unable to listWebACLs', function (done) {
            const cache = createErrorCache();
            cloudwatchMetricsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list WAFV2 web ACLs:')
                done();
            });
        });
        it('should unknown if unable to get web acl details', function (done) {
            const cache = createCache([webACLs[0]], null)
            cloudwatchMetricsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get web acl details:')
                done();
            });
        });
    });
});
